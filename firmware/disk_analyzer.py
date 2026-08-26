#!/usr/bin/env python3
"""
D1 — Disk Image Analyzer
Reads MBR/GPT partitions, extracts file metadata, recovers deleted files, timeline analysis.
"""

import struct
import os
import sys
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict


class DiskAnalyzer:
    """Core disk image forensics engine."""

    MBR_SIGNATURE = b"\x55\xAA"
    GPT_SIGNATURE = b"EFI PART"
    NTFS_MAGIC = b"NTFS    "
    FAT32_MAGIC = b"MSDOS5.0"
    EXT2_MAGIC = b"\x53\xef"
    EXFAT_MAGIC = b"EXFAT"

    PARTITION_TYPE_MAP = {
        0x00: "Empty",
        0x01: "FAT12",
        0x04: "FAT16 <32MB",
        0x05: "Extended",
        0x06: "FAT16 >32MB",
        0x07: "NTFS/exFAT/HPFS",
        0x08: "AIX bootable",
        0x0B: "FAT32 CHS",
        0x0C: "FAT32 LBA",
        0x0E: "FAT16 LBA",
        0x11: "Hidden FAT12",
        0x12: "Compaq diagnostics",
        0x14: "Hidden FAT16 <32MB",
        0x16: "Hidden FAT16 >32MB",
        0x17: "Hidden NTFS",
        0x1B: "Hidden FAT32",
        0x1C: "Hidden FAT32 LBA",
        0x1E: "Hidden FAT16 LBA",
        0x27: "Windows Recovery",
        0x39: "Plan 9",
        0x41: "Linux swap",
        0x42: "Linux filesystem",
        0x82: "Linux swap",
        0x83: "Linux filesystem",
        0x85: "Linux extended",
        0xA5: "FreeBSD",
        0xEE: "GPT protective",
        0xEF: "EFI System",
        0xFD: "Linux RAID",
    }

    def __init__(self, image_path: str):
        self.image_path = image_path
        self.data = None
        self.file_size = 0
        self.partitions = []
        self.files = []
        self.deleted_files = []

    def load_image(self) -> bool:
        """Load disk image file."""
        if not os.path.exists(self.image_path):
            print(f"[ERROR] File not found: {self.image_path}")
            return False
        self.file_size = os.path.getsize(self.image_path)
        if self.file_size == 0:
            print(f"[ERROR] File is empty: {self.image_path}")
            return False
        with open(self.image_path, "rb") as f:
            self.data = f.read()
        print(f"[+] Loaded disk image: {self.image_path} ({self.file_size:,} bytes)")
        return True

    def calculate_hashes(self) -> dict:
        """Calculate hashes of the disk image."""
        hashes = {}
        for name, algo in [("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)]:
            h = algo()
            h.update(self.data)
            hashes[name] = h.hexdigest()
        return hashes

    def parse_mbr(self) -> dict:
        """Parse Master Boot Record (MBR) partition table."""
        if len(self.data) < 512:
            return {"error": "Image too small for MBR"}

        mbr = self.data[:512]
        sig = mbr[510:512]
        if sig != self.MBR_SIGNATURE:
            return {"error": "Invalid MBR signature"}

        partitions = []
        for i in range(4):
            entry_offset = 446 + (i * 16)
            entry = mbr[entry_offset:entry_offset + 16]

            status = entry[0]
            p_type = entry[4]
            lba_start = struct.unpack_from("<I", entry, 8)[0]
            num_sectors = struct.unpack_from("<I", entry, 12)[0]

            type_name = self.PARTITION_TYPE_MAP.get(p_type, f"Unknown (0x{p_type:02x})")

            if p_type != 0x00:
                partitions.append({
                    "index": i + 1,
                    "status": f"0x{status:02x}" + (" bootable" if status == 0x80 else ""),
                    "type": type_name,
                    "type_hex": f"0x{p_type:02x}",
                    "lba_start": lba_start,
                    "num_sectors": num_sectors,
                    "size_mb": round(num_sectors * 512 / (1024 * 1024), 2),
                })

        return {
            "type": "MBR",
            "signature": sig.hex(),
            "partitions": partitions,
        }

    def parse_gpt(self) -> dict:
        """Parse GUID Partition Table (GPT)."""
        if len(self.data) < 512:
            return {"error": "Image too small for GPT"}

        sig = self.data[:8]
        if sig != self.GPT_SIGNATURE:
            return {"error": "Invalid GPT signature"}

        revision = struct.unpack_from("<I", self.data, 8)[0]
        header_size = struct.unpack_from("<I", self.data, 12)[0]
        first_lba = struct.unpack_from("<Q", self.data, 24)[0]
        last_lba = struct.unpack_from("<Q", self.data, 32)[0]
        partition_entries_lba = struct.unpack_from("<Q", self.data, 72)[0]
        num_partitions = struct.unpack_from("<I", self.data, 80)[0]
        partition_entry_size = struct.unpack_from("<I", self.data, 84)[0]

        partitions = []
        if partition_entries_lba > 0 and partition_entry_size > 0:
            entries_start = partition_entries_lba * 512
            for i in range(min(num_partitions, 128)):
                entry_offset = entries_start + (i * partition_entry_size)
                if entry_offset + partition_entry_size > len(self.data):
                    break
                entry = self.data[entry_offset:entry_offset + partition_entry_size]
                if entry[:16] == b"\x00" * 16:
                    continue
                part_type = entry[:16]
                part_start = struct.unpack_from("<Q", entry, 32)[0]
                part_end = struct.unpack_from("<Q", entry, 40)[0]
                name_raw = entry[56:128]
                name = name_raw.decode("utf-16-le", errors="replace").rstrip("\x00")

                partitions.append({
                    "index": i + 1,
                    "type_guid": part_type.hex(),
                    "name": name,
                    "first_lba": part_start,
                    "last_lba": part_end,
                    "size_mb": round((part_end - part_start + 1) * 512 / (1024 * 1024), 2),
                })

        return {
            "type": "GPT",
            "signature": sig.decode("ascii"),
            "revision": f"{(revision >> 16) & 0xffff}.{revision & 0xffff}",
            "header_size": header_size,
            "first_lba": first_lba,
            "last_lba": last_lba,
            "partitions": partitions,
        }

    def detect_partition_scheme(self) -> dict:
        """Detect whether MBR or GPT."""
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

    def extract_file_metadata(self, partition_offset: int = 0, max_files: int = 50) -> list:
        """Extract file metadata from a partition (simplified FAT/NTFS parsing)."""
        files = []
        if partition_offset + 512 > len(self.data):
            return files

        bpb = self.data[partition_offset:partition_offset + 512]
        bytes_per_sector = struct.unpack_from("<H", bpb, 11)[0]
        if bytes_per_sector == 0 or bytes_per_sector > 4096:
            bytes_per_sector = 512

        oem_id = bpb[3:11].decode("ascii", errors="replace")
        vol_label = bpb[43:54].decode("ascii", errors="replace")

        root_dir_offset = partition_offset + bytes_per_sector * 32
        if root_dir_offset + 512 > len(self.data):
            root_dir_offset = partition_offset + bytes_per_sector

        for i in range(min(max_files, 16)):
            entry_offset = root_dir_offset + (i * 32)
            if entry_offset + 32 > len(self.data):
                break
            entry = self.data[entry_offset:entry_offset + 32]

            if entry[0] == 0x00:
                break
            if entry[0] == 0xE5:
                name_raw = b"\x05" + entry[1:8]
                ext_raw = entry[8:11]
                deleted = True
            elif entry[11] == 0x0F:
                continue
            else:
                name_raw = entry[0:8]
                ext_raw = entry[8:11]
                deleted = False

            name = name_raw.decode("ascii", errors="replace").strip()
            ext = ext_raw.decode("ascii", errors="replace").strip()
            full_name = f"{name}.{ext}" if ext else name

            file_size = struct.unpack_from("<I", entry, 28)[0]
            create_date = struct.unpack_from("<H", entry, 16)[0]
            create_time = struct.unpack_from("<H", entry, 14)[0]

            files.append({
                "name": full_name,
                "size": file_size,
                "deleted": deleted,
                "create_date": self._fat_date_to_str(create_date, create_time),
                "attributes": entry[11],
            })

        self.files = [f for f in files if not f["deleted"]]
        self.deleted_files = [f for f in files if f["deleted"]]
        return files

    def scan_deleted_files(self) -> list:
        """Scan for deleted file signatures across the image."""
        signatures = [
            (b"\x89PNG\r\n\x1a\n", "PNG image"),
            (b"\xff\xd8\xff\xe0", "JPEG image"),
            (b"\xff\xd8\xff\xe1", "JPEG image (Exif)"),
            (b"%PDF", "PDF document"),
            (b"PK\x03\x04", "ZIP archive"),
            (b"Rar!\x1a\x07", "RAR archive"),
            (b"\x1f\x8b\x08", "GZIP archive"),
            (b"SQLite format 3", "SQLite database"),
            (b"\xd0\xcf\x11\xe0", "MS Office document"),
            (b"BM", "BMP image"),
            (b"GIF87a", "GIF image"),
            (b"GIF89a", "GIF image"),
        ]

        deleted = []
        for sig_bytes, desc in signatures:
            offset = 0
            count = 0
            while count < 5:
                pos = self.data.find(sig_bytes, offset)
                if pos == -1:
                    break
                deleted.append({
                    "offset": pos,
                    "type": desc,
                    "signature": sig_bytes.hex(),
                })
                offset = pos + len(sig_bytes)
                count += 1

        return deleted

    def build_timeline(self) -> list:
        """Build a forensic timeline from partition metadata."""
        events = []
        for f in self.files:
            if f.get("create_date") and f["create_date"] != "0000-00-00 00:00:00":
                events.append({
                    "timestamp": f["create_date"],
                    "type": "file_created",
                    "name": f["name"],
                    "size": f["size"],
                })
        events.sort(key=lambda x: x["timestamp"])
        return events

    def full_analysis(self) -> dict:
        """Run complete disk image analysis."""
        if self.data is None:
            if not self.load_image():
                return {}

        print("[*] Running disk image analysis...")
        print("[*] Calculating hashes...")
        hashes = self.calculate_hashes()

        print("[*] Detecting partition scheme...")
        partitions = self.detect_partition_scheme()

        print("[*] Extracting file metadata...")
        files = self.extract_file_metadata()

        print("[*] Scanning for deleted files...")
        deleted = self.scan_deleted_files()

        print("[*] Building timeline...")
        timeline = self.build_timeline()

        result = {
            "file": self.image_path,
            "size": self.file_size,
            "hashes": hashes,
            "partitions": partitions,
            "files": files,
            "active_files": len(self.files),
            "deleted_files": len(self.deleted_files),
            "deleted_signatures": deleted,
            "timeline": timeline,
        }

        self._print_summary(result)
        return result

    def export_json(self, output_path: str):
        """Export analysis results to JSON."""
        result = self.full_analysis()
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"[+] Results exported to {output_path}")

    def _fat_date_to_str(self, date_val: int, time_val: int) -> str:
        """Convert FAT date/time to string."""
        if date_val == 0:
            return "0000-00-00 00:00:00"
        try:
            year = ((date_val >> 9) & 0x7F) + 1980
            month = (date_val >> 5) & 0x0F
            day = date_val & 0x1F
            hour = (time_val >> 11) & 0x1F
            minute = (time_val >> 5) & 0x3F
            second = (time_val & 0x1F) * 2
            return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
        except (ValueError, OverflowError):
            return "0000-00-00 00:00:00"

    def _print_summary(self, result: dict):
        """Print analysis summary."""
        print("\n" + "=" * 60)
        print("  D2 — Disk Image Analyzer — Analysis Report")
        print("=" * 60)
        print(f"  File: {result['file']}")
        print(f"  Size: {result['size']:,} bytes")
        print(f"  MD5:  {result['hashes'].get('md5', 'N/A')}")
        print(f"  SHA1: {result['hashes'].get('sha1', 'N/A')}")

        if "type" in result["partitions"] and result["partitions"]["type"] != "error":
            pt = result["partitions"]
            print(f"\n  Partition Scheme: {pt['type']}")
            for p in pt.get("partitions", []):
                print(f"    Partition {p['index']}: {p['type']} ({p['size_mb']} MB)")
        else:
            print(f"\n  Partition Scheme: {result['partitions'].get('error', 'Unknown')}")

        print(f"\n  Active Files: {result['active_files']}")
        print(f"  Deleted Files Found: {result['deleted_files']}")
        print(f"  Deleted File Signatures: {len(result['deleted_signatures'])}")

        if result["deleted_signatures"]:
            print("\n  --- Deleted File Signatures ---")
            for s in result["deleted_signatures"][:10]:
                print(f"    0x{s['offset']:08x}: {s['type']}")

        if result["timeline"]:
            print(f"\n  Timeline: {len(result['timeline'])} events")
            for e in result["timeline"][:5]:
                print(f"    {e['timestamp']} {e['type']}: {e['name']}")

        print("=" * 60)

    def generate_test_image(self, output_path: str, size: int = 2 * 1024 * 1024):
        """Generate a synthetic test disk image for testing."""
        print(f"[*] Generating test disk image ({size:,} bytes)...")
        data = bytearray(size)

        import random
        random.seed(99)
        for i in range(0, min(size, 512 * 100), 4):
            struct.pack_into("<I", data, i, random.getrandbits(32))

        # MBR signature
        data[510] = 0x55
        data[511] = 0xAA

        # Partition 1: NTFS
        entry = 446
        data[entry] = 0x80  # bootable
        data[entry + 4] = 0x07  # NTFS
        struct.pack_into("<I", data, entry + 8, 2048)
        struct.pack_into("<I", data, entry + 12, (size // 512) - 2048)

        # Partition 2: Linux
        entry2 = 446 + 16
        data[entry2 + 4] = 0x83  # Linux
        struct.pack_into("<I", data, entry2 + 8, (size // 512) // 2)
        struct.pack_into("<I", data, entry2 + 12, (size // 512) // 4)

        # Embed NTFS BPB at sector 1
        bpb_offset = 512
        data[bpb_offset:bpb_offset + 3] = b"\xeb\x58\x90"
        data[bpb_offset + 3:bpb_offset + 11] = b"MSDOS5.0"
        struct.pack_into("<H", data, bpb_offset + 11, 512)  # bytes per sector
        data[bpb_offset + 21] = 0xF8  # media type
        data[bpb_offset + 43:bpb_offset + 54] = b"TESTDISK   "

        # Embed file signatures
        sig_offsets = {
            0x10000: b"\x89PNG\r\n\x1a\n",  # PNG
            0x20000: b"\xff\xd8\xff\xe0",  # JPEG
            0x30000: b"%PDF-1.4",  # PDF
            0x40000: b"PK\x03\x04",  # ZIP
            0x50000: b"SQLite format 3",  # SQLite
        }
        for off, sig in sig_offsets.items():
            if off + len(sig) < size:
                data[off:off + len(sig)] = sig

        # Embed root directory entries
        dir_offset = 512 * 32
        file_names = [
            (b"DOCUMENT TXT", 4096, False),
            (b"\x05ELETED~DOC", 8192, True),
            (b"SYSTEM  SYS", 1024, False),
            (b"\x05MP_DATA DAT", 65536, True),
            (b"LOGS    TXT", 32768, False),
        ]
        for i, (name, size_val, deleted) in enumerate(file_names):
            off = dir_offset + (i * 32)
            if off + 32 > size:
                break
            if deleted:
                data[off] = 0xE5
            data[off + 1:off + 11] = name[:11]
            data[off + 11] = 0x20  # archive attribute
            struct.pack_into("<I", data, off + 28, size_val)

        with open(output_path, "wb") as f:
            f.write(data)
        print(f"[+] Test image written: {output_path}")
        return output_path


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="D2 — Disk Image Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 disk_analyzer.py --image disk.raw --output report.json"
    )
    parser.add_argument("--image", "-i", help="Path to disk image file")
    parser.add_argument("--output", "-o", help="Export results to JSON file")
    parser.add_argument("--generate-test", "-g", help="Generate a test disk image", metavar="PATH")
    parser.add_argument("--mbr", action="store_true", help="Parse MBR only")
    parser.add_argument("--gpt", action="store_true", help="Parse GPT only")
    parser.add_argument("--hash", action="store_true", help="Calculate hashes only")
    args = parser.parse_args()

    if args.generate_test:
        analyzer = DiskAnalyzer(args.generate_test)
        analyzer.generate_test_image(args.generate_test)
        analyzer.load_image()
        analyzer.full_analysis()
        return

    if not args.image:
        parser.print_help()
        sys.exit(1)

    analyzer = DiskAnalyzer(args.image)

    if args.hash:
        analyzer.load_image()
        hashes = analyzer.calculate_hashes()
        for algo, digest in hashes.items():
            print(f"  {algo.upper():>8}: {digest}")
        return

    if args.mbr:
        analyzer.load_image()
        result = analyzer.parse_mbr()
        print(json.dumps(result, indent=2))
        return

    if args.gpt:
        analyzer.load_image()
        result = analyzer.parse_gpt()
        print(json.dumps(result, indent=2))
        return

    if args.output:
        analyzer.export_json(args.output)
    else:
        analyzer.full_analysis()


if __name__ == "__main__":
    main()
