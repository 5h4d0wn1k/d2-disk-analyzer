#!/usr/bin/env python3
"""Build a real FAT32 disk image fixture (MBR + FAT32 partition) for D2 Disk Analyzer.

Layout (all little-endian):
  - Sector 0: MBR with one active partition entry (type 0x0C, FAT32 LBA) at LBA 2048.
  - Sector 2048: FAT32 BIOS Parameter Block (BPB) + boot code.
  - Reserved sectors (32). FAT1 starts at cluster-relative sector from BPB.
  - Two FAT copies, then root cluster, then data region.
  - Root directory contains both live and deleted (0xE5) 8.3 entries.
  - A data cluster holds a file body; the FAT chain links root file clusters.
"""
import os
import struct

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

BYTES_PER_SECTOR = 512
SECTORS_PER_CLUSTER = 1
RESERVED_SECTORS = 32
NUM_FATS = 2
FAT_SIZE_SECTORS = 8
ROOT_CLUSTER = 2
FIRST_DATA_SECTOR = RESERVED_SECTORS + (NUM_FATS * FAT_SIZE_SECTORS)


def sector(block):
    return block + b"\x00" * (BYTES_PER_SECTOR - len(block))


def build_fat32_bpb():
    bpb = bytearray(512)
    # Jump instruction
    bpb[0:3] = b"\xeb\x58\x90"
    # OEM name
    bpb[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", bpb, 11, BYTES_PER_SECTOR)          # bytes per sector
    bpb[13] = SECTORS_PER_CLUSTER                               # sectors per cluster
    struct.pack_into("<H", bpb, 14, RESERVED_SECTORS)           # reserved sectors
    bpb[16] = NUM_FATS                                          # number of FATs
    struct.pack_into("<H", bpb, 17, 32)                         # root entries (FAT12/16; 0 for FAT32)
    struct.pack_into("<H", bpb, 19, 0)                          # total sectors 16-bit
    bpb[21] = 0xF8                                              # media type
    struct.pack_into("<H", bpb, 22, 0)                          # sectors per FAT (FAT12/16)
    struct.pack_into("<H", bpb, 24, 63)                         # sectors per track
    struct.pack_into("<H", bpb, 26, 255)                        # heads
    struct.pack_into("<I", bpb, 28, 2048)                       # hidden sectors (start LBA)
    struct.pack_into("<I", bpb, 32, 0)                          # total sectors 32-bit (unused here)
    struct.pack_into("<I", bpb, 36, FAT_SIZE_SECTORS)           # sectors per FAT (FAT32)
    struct.pack_into("<H", bpb, 40, 0)                          # ext flags
    struct.pack_into("<H", bpb, 42, 0)                          # FS version
    struct.pack_into("<I", bpb, 44, ROOT_CLUSTER)               # root cluster
    struct.pack_into("<H", bpb, 48, 1)                          # FSInfo sector
    struct.pack_into("<H", bpb, 50, 6)                          # backup boot sector
    bpb[66:74] = b"NO_NAME "  # 8 chars: "NO_NAME"+1 space
    bpb[82:90] = b"FAT32   "
    return bpb


def fat_dir_entry(name8, ext3, size, first_cluster, deleted=False, attr=0x20):
    e = bytearray(32)
    if deleted:
        e[0] = 0xE5
        e[1:9] = name8.ljust(8, b" ")[:8]
    else:
        e[0:8] = name8.ljust(8, b" ")[:8]
    e[8:11] = ext3.ljust(3, b" ")[:3]
    e[11] = attr
    # FAT32 extended timestamps / cluster pointers (offsets per FAT spec):
    struct.pack_into("<H", e, 14, 0x7A3F)  # create time 15:30:2x
    struct.pack_into("<H", e, 16, 0x4A31)  # create date 2024-01-15
    struct.pack_into("<H", e, 18, 0x4A31)  # last access date
    struct.pack_into("<H", e, 20, 0x0000)  # high word of first cluster (FAT32)
    struct.pack_into("<H", e, 22, 0x7A3F)  # write time
    struct.pack_into("<H", e, 24, 0x4A31)  # write date 2024-01-15
    struct.pack_into("<H", e, 26, 0 if deleted else first_cluster)  # low word of first cluster
    struct.pack_into("<I", e, 28, size)
    return e


def main():
    disk = bytearray()
    # Sector 0: MBR
    mbr = bytearray(512)
    # active partition 1 at index 0
    mbr[446] = 0x80                 # bootable
    mbr[446 + 4] = 0x0C             # FAT32 LBA
    struct.pack_into("<I", mbr, 446 + 8, 2048)      # start LBA
    struct.pack_into("<I", mbr, 446 + 12, 4096)     # num sectors
    mbr[510:512] = b"\x55\xAA"
    disk += mbr

    # Sectors 1..2047: unused padding (zeros)
    disk += b"\x00" * (2047 * 512)

    # Sector 2048: FAT32 BPB
    bpb = build_fat32_bpb()
    disk += bytes(bpb)
    # Reserved sectors 2049..(2048+31)
    disk += b"\x00" * ((RESERVED_SECTORS - 1) * 512)

    fat_start = 2048 + RESERVED_SECTORS
    data_start = 2048 + FIRST_DATA_SECTOR
    total_sectors = 4096

    # Build FAT (cluster 0 and 1 reserved, cluster 2 = root, cluster 3 = README file body)
    fat = bytearray(FAT_SIZE_SECTORS * 512)
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)   # media
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)   # EOF
    struct.pack_into("<I", fat, 8, 0x0FFFFFFF)   # root cluster = EOF (no further clusters)
    # cluster 3 -> file body cluster
    struct.pack_into("<I", fat, 12, 0x0FFFFFFF)  # README.TXT starts at cluster 3, single cluster -> EOF
    fat1 = bytes(fat)
    fat2 = fat1

    disk += fat1 + fat2

    # Root directory at root cluster (cluster 2): data_start + (2-2)*sectors_per_cluster = data_start
    root = bytearray()
    root += bytes(fat_dir_entry(b"README", b"TXT", 61, 3, deleted=False))
    root += bytes(fat_dir_entry(b"HIDDEN", b"BIN", 5120, 4, deleted=True))   # deleted file hint
    root += bytes(fat_dir_entry(b"DOCUME", b"TXT", 2048, 5, deleted=False))
    root += bytes(fat_dir_entry(b"GONE", b"DAT", 999, 6, deleted=True))      # deleted file hint
    # pad root cluster to one sector
    root += b"\x00" * (512 - len(root))
    disk += root

    # Cluster 3: README.TXT body
    body = b"Hello forensic investigator. This is a real FAT32 file body.\n"
    body = body + b"\x00" * (512 - len(body))
    disk += body

    # Fill remaining sectors up to partition end + one spare disk sector
    cur = len(disk)
    target = (2048 + total_sectors) * 512
    if cur < target:
        disk += b"\x00" * (target - cur)
    # extend disk to a full 8 MB with an unallocated-region signature for grep
    disk_size = 8 * 1024 * 1024
    if len(disk) < disk_size:
        disk += b"\x00" * (disk_size - len(disk))

    # Embed an unallocated-recoverable string signature in a slack/deleted region
    marker = b"SALVAGEME_FORENSIC_MARKER"
    disk[0x1000:0x1000 + len(marker)] = marker

    os.makedirs(FIXTURE_DIR, exist_ok=True)
    path = os.path.join(FIXTURE_DIR, "disk.img")
    with open(path, "wb") as f:
        f.write(bytes(disk))
    print("Wrote %s (%d bytes)" % (path, len(disk)))


if __name__ == "__main__":
    main()
