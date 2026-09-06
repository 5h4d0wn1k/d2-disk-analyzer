#!/usr/bin/env python3
"""
D2 — Disk Image Analyzer
Hand-parses MBR/GPT partition tables, FAT32 BPB + FAT chain + directory entries,
reports partitions/clusters/deleted-file hints, scans unallocated/raw regions by grep.
"""

import struct
import os
import sys
import json
import hashlib


class DiskAnalyzer:
    MBR_SIGNATURE = b"\x55\xAA"
    GPT_SIGNATURE = b"EFI PART"
    FAT32_MAGIC = b"MSDOS5.0"

    PARTITION_TYPE_MAP = {
        0x00: "Empty", 0x01: "FAT12", 0x04: "FAT16 <32MB", 0x05: "Extended",
        0x06: "FAT16 >32MB", 0x07: "NTFS/exFAT/HPFS", 0x0B: "FAT32 CHS",
        0x0C: "FAT32 LBA", 0x0E: "FAT16 LBA", 0x17: "Hidden NTFS",
        0x1B: "Hidden FAT32", 0x82: "Linux swap", 0x83: "Linux filesystem",
        0xEE: "GPT protective", 0xEF: "EFI System",
    }

    def __init__(self, image_path):
        self.image_path = image_path
        self.data = None
        self.file_size = 0

    def load_image(self):
        if not os.path.exists(self.image_path):
            raise FileNotFoundError(self.image_path)
        self.file_size = os.path.getsize(self.image_path)
        if self.file_size == 0:
            raise ValueError("Empty disk image")
        with open(self.image_path, "rb") as f:
            self.data = f.read()
        return True

    def calculate_hashes(self):
        out = {}
        for name, algo in [("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)]:
            h = algo()
            h.update(self.data)
            out[name] = h.hexdigest()
        return out

    # ---------------- MBR / GPT ----------------
    def parse_mbr(self):
        if len(self.data) < 512:
            return {"error": "Image too small for MBR"}
        mbr = self.data[:512]
        if mbr[510:512] != self.MBR_SIGNATURE:
            return {"error": "Invalid MBR signature"}
        partitions = []
        for i in range(4):
            o = 446 + (i * 16)
            entry = mbr[o:o + 16]
            status = entry[0]
            p_type = entry[4]
            start = struct.unpack_from("<I", entry, 8)[0]
            num = struct.unpack_from("<I", entry, 12)[0]
            if p_type == 0x00:
                continue
            partitions.append({
                "index": i + 1,
                "status": ("0x%02x bootable" % status) if status == 0x80 else "0x%02x" % status,
                "type": self.PARTITION_TYPE_MAP.get(p_type, "Unknown 0x%02x" % p_type),
                "type_hex": "0x%02x" % p_type,
                "lba_start": start,
                "num_sectors": num,
                "size_mb": round(num * 512 / (1024 * 1024), 2),
            })
        return {"type": "MBR", "signature": mbr[510:512].hex(), "partitions": partitions}

    def parse_gpt(self):
        if len(self.data) < 512:
            return {"error": "Image too small for GPT"}
        if self.data[:8] != self.GPT_SIGNATURE:
            return {"error": "Invalid GPT signature"}
        entries_lba = struct.unpack_from("<Q", self.data, 72)[0]
        num = struct.unpack_from("<I", self.data, 80)[0]
        esize = struct.unpack_from("<I", self.data, 84)[0]
        partitions = []
        entries_start = entries_lba * 512
        for i in range(min(num, 128)):
            o = entries_start + (i * esize)
            if o + esize > len(self.data):
                break
            entry = self.data[o:o + esize]
            if entry[:16] == b"\x00" * 16:
                continue
            start = struct.unpack_from("<Q", entry, 32)[0]
            end = struct.unpack_from("<Q", entry, 40)[0]
            name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
            partitions.append({
                "index": i + 1,
                "type_guid": entry[:16].hex(),
                "name": name,
                "first_lba": start,
                "last_lba": end,
                "size_mb": round((end - start + 1) * 512 / (1024 * 1024), 2),
            })
        return {"type": "GPT", "signature": "EFI PART", "partitions": partitions}

    def detect_partition_scheme(self):
        if len(self.data) < 512:
            return {"error": "Image too small"}
        if self.data[:8] == self.GPT_SIGNATURE:
            return self.parse_gpt()
        if self.data[510:512] == self.MBR_SIGNATURE:
            mbr = self.parse_mbr()
            for p in mbr.get("partitions", []):
                if p["type_hex"] == "0xee":
                    return self.parse_gpt()
            return mbr
        return {"error": "No valid partition table found"}

    # ---------------- FAT32 ----------------
    def fat32_bpb(self, partition_lba):
        """Return parsed FAT32 BPB dict or None if not FAT32."""
        o = partition_lba * 512
        if o + 512 > len(self.data):
            return None
        bpb = self.data[o:o + 512]
        if bpb[3:11] != self.FAT32_MAGIC:
            return None
        bytes_per_sector = struct.unpack_from("<H", bpb, 11)[0] or 512
        return {
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": bpb[13],
            "reserved_sectors": struct.unpack_from("<H", bpb, 14)[0],
            "num_fats": bpb[16],
            "sectors_per_fat": struct.unpack_from("<I", bpb, 36)[0],
            "root_cluster": struct.unpack_from("<I", bpb, 44)[0],
            "hidden_sectors": struct.unpack_from("<I", bpb, 28)[0],
        }

    def _fat32_first_data_sector(self, bpb, partition_lba):
        return partition_lba + bpb["reserved_sectors"] + (bpb["num_fats"] * bpb["sectors_per_fat"])

    def _fat32_cluster_sector(self, bpb, cluster, partition_lba):
        return self._fat32_first_data_sector(bpb, partition_lba) + ((cluster - 2) * bpb["sectors_per_cluster"])

    def fat32_fat_entry(self, bpb, fat_start_lba, cluster):
        """Read a FAT32 32-bit entry for a cluster from the primary FAT."""
        off = fat_start_lba * 512 + (cluster * 4)
        if off + 4 > len(self.data):
            return 0x0FFFFFFF
        return struct.unpack_from("<I", self.data, off)[0] & 0x0FFFFFFF

    def fat32_read_chain(self, bpb, cluster, partition_lba, max_clusters=100000):
        """Walk the FAT chain from a starting cluster, returning a list of cluster numbers."""
        fat_start = partition_lba + bpb["reserved_sectors"]
        chain = []
        seen = set()
        c = cluster
        while c and c < 0x0FFFFFF8 and len(chain) < max_clusters:
            if c in seen:
                break
            seen.add(c)
            chain.append(c)
            nxt = self.fat32_fat_entry(bpb, fat_start, c)
            if nxt == 0 or nxt == 0x0FFFFFFF:
                break
            c = nxt
        return chain

    def fat32_read_cluster(self, bpb, cluster, partition_lba):
        sec = self._fat32_cluster_sector(bpb, cluster, partition_lba)
        off = sec * bpb["bytes_per_sector"]
        length = bpb["sectors_per_cluster"] * bpb["bytes_per_sector"]
        return self.data[off:off + length]

    def fat32_parse_root(self, bpb, partition_lba, max_entries=256):
        """Parse root directory (single cluster for the fixture)."""
        files = []
        cluster = bpb["root_cluster"]
        raw = self.fat32_read_cluster(bpb, cluster, partition_lba)
        for i in range(min(max_entries, len(raw) // 32)):
            e = raw[i * 32:(i + 1) * 32]
            if len(e) < 32:
                break
            if e[0] == 0x00:
                break
            if e[11] == 0x0F:
                continue
            if e[0] == 0xE5:
                deleted = True
                name_raw = e[1:8]
                ext_raw = e[8:11]
                first_cluster = 0
            else:
                deleted = False
                name_raw = e[0:8]
                ext_raw = e[8:11]
                first_cluster = (struct.unpack_from("<H", e, 20)[0] << 16) | struct.unpack_from("<H", e, 26)[0]
            name = name_raw.decode("ascii", errors="replace").strip().rstrip("\x20")
            ext = ext_raw.decode("ascii", errors="replace").strip().rstrip("\x20")
            full = ("%s.%s" % (name, ext)) if ext else name
            size = struct.unpack_from("<I", e, 28)[0]
            date_raw = struct.unpack_from("<H", e, 16)[0]
            time_raw = struct.unpack_from("<H", e, 14)[0]
            chain = self.fat32_read_chain(bpb, first_cluster, partition_lba) if (first_cluster and not deleted) else []
            files.append({
                "name": full,
                "size": size,
                "deleted": deleted,
                "first_cluster": first_cluster,
                "chain": chain,
                "create_date": self._fat_date_to_str(date_raw, time_raw),
            })
        active = [f for f in files if not f["deleted"]]
        deleted_files = [f for f in files if f["deleted"]]
        return {"active": active, "deleted": deleted_files, "all": files}

    def fat32_recover(self, bpb, partition_lba, root_fs, filename):
        """Recover an active file body by walking its FAT chain and concatenating clusters."""
        entry = [f for f in root_fs["all"] if f["name"] == filename]
        if not entry or entry[0]["deleted"]:
            return None
        e = entry[0]
        chain = self.fat32_read_chain(bpb, e["first_cluster"], partition_lba)
        parts = [self.fat32_read_cluster(bpb, c, partition_lba) for c in chain]
        body = b"".join(parts)[:e["size"]]
        return body

    # ---------------- raw / unallocated grep ----------------
    def raw_grep(self, pattern):
        """Find all byte offsets of a pattern in the raw image."""
        out = []
        offset = 0
        while True:
            pos = self.data.find(pattern, offset)
            if pos == -1:
                break
            out.append(pos)
            offset = pos + len(pattern)
        return out

    # ---------------- misc ----------------
    def _fat_date_to_str(self, date_val, time_val):
        if date_val == 0:
            return "0000-00-00 00:00:00"
        year = ((date_val >> 9) & 0x7F) + 1980
        month = (date_val >> 5) & 0x0F
        day = date_val & 0x1F
        hour = (time_val >> 11) & 0x1F
        minute = (time_val >> 5) & 0x3F
        second = (time_val & 0x1F) * 2
        try:
            return "%04d-%02d-%02d %02d:%02d:%02d" % (year, month, day, hour, minute, second)
        except (ValueError, OverflowError):
            return "0000-00-00 00:00:00"

    def full_analysis(self):
        if self.data is None:
            self.load_image()
        result = {
            "file": self.image_path,
            "size": self.file_size,
            "hashes": self.calculate_hashes(),
            "partition_scheme": self.detect_partition_scheme(),
        }

        # FAT32 partition detection: try partition 1 LBA if MBR, else GPT partitions
        fat = {}
        scheme = result["partition_scheme"]
        if scheme.get("type") == "MBR" and scheme.get("partitions"):
            lba = scheme["partitions"][0]["lba_start"]
            bpb = self.fat32_bpb(lba)
            if bpb:
                fs = self.fat32_parse_root(bpb, lba)
                result["filesystem"] = "FAT32"
                result["bpb"] = bpb
                result["root_dir"] = fs
                fat["recovered_README"] = self._safe_body(bpb, lba)
        result["fat32"] = fat if fat else None

        marker = self.raw_grep(b"SALVAGEME_FORENSIC_MARKER")
        result["raw_grep"] = marker
        return result

    def _safe_body(self, bpb, lba):
        try:
            fs = self.fat32_parse_root(bpb, lba)
            body = self.fat32_recover(bpb, lba, fs, "README.TXT")
            return body.decode("ascii", errors="replace") if body else None
        except Exception:
            return None

    def _print_summary(self, result):
        print("=" * 60)
        print("  D2 — Disk Image Analyzer — Analysis Report")
        print("=" * 60)
        print("  File: %s" % result["file"])
        print("  Size: %d bytes" % result["size"])
        print("  MD5:  %s" % result["hashes"]["md5"])
        scheme = result["partition_scheme"]
        if scheme.get("type") in ("MBR", "GPT"):
            print("  Partition Scheme: %s" % scheme["type"])
            for p in scheme.get("partitions", []):
                print("    P%d: %s (%s, %s MB)" % (p["index"], p["name"] if "name" in p else p["type"], p.get("type", p.get("type_hex", "")), p["size_mb"]))
        else:
            print("  Partition Scheme: %s" % scheme.get("error", "unknown"))

        if result.get("filesystem"):
            print("  Filesystem: %s" % result["filesystem"])
            fs = result["root_dir"]
            print("  Active files: %d" % len(fs["active"]))
            for f in fs["active"]:
                print("    %-14s %8d bytes  cluster %s" % (f["name"], f["size"], f["chain"]))
            print("  Deleted-file hints: %d" % len(fs["deleted"]))
            for f in fs["deleted"]:
                print("    [DEL] %-14s %8d bytes" % (f["name"], f["size"]))
            if result["fat32"] and result["fat32"].get("recovered_README"):
                print("  Recovered README.TXT body: %r" % result["fat32"]["recovered_README"])

        if result.get("raw_grep"):
            print("  Raw/unallocated grep hits: %d" % len(result["raw_grep"]))
            for off in result["raw_grep"]:
                print("    0x%x" % off)
        print("=" * 60)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="D2 — Disk Image Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--image", "-i", help="Path to disk image file")
    parser.add_argument("--output", "-o", help="Export results to JSON file")
    parser.add_argument("--demo", action="store_true", help="Analyze built-in fixture")
    parser.add_argument("--grep", "-g", help="Grep raw image for a byte pattern")
    args = parser.parse_args()

    if args.demo:
        base = os.path.dirname(os.path.abspath(sys.argv[0]))
        if os.path.basename(base) == "firmware":
            base = os.path.dirname(base)
        fixture = os.path.join(base, "tests", "fixtures", "disk.img")
        if not os.path.isfile(fixture):
            print("[ERROR] Fixture not found: %s" % fixture)
            sys.exit(1)
        da = DiskAnalyzer(fixture)
        da.load_image()
        result = da.full_analysis()
        out_dir = os.path.join(base, "reports")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "d2_report.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        da._print_summary(result)
        print("Report written to %s" % out_path)
        sys.exit(0)

    if not args.image:
        parser.print_help()
        sys.exit(1)

    da = DiskAnalyzer(args.image)
    da.load_image()

    if args.grep:
        hits = da.raw_grep(args.grep.encode())
        for off in hits:
            print("0x%x" % off)
        sys.exit(0)

    result = da.full_analysis()
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print("Report written to %s" % args.output)
    da._print_summary(result)
    sys.exit(0)


if __name__ == "__main__":
    main()
