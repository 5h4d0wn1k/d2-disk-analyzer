# D2 — Disk Image Analyzer

Hand-parses MBR/GPT partition tables and FAT32 filesystems (BPB + FAT chain + directory entries), reports partitions/clusters/deleted-file hints, and greps raw/unallocated regions.

## IMPORTANT: Read before use.

This tool is for **authorized educational and blue-team analysis only**. Analyze disk images only from systems you own or are explicitly permitted to examine. The bundled fixture is fully synthetic; no personal data.

## Features

- **MBR partition table parsing** by hand (struct): status, type, LBA start, sector count, size
- **GPT partition table parsing** by hand: type GUID, name, LBA range
- **FAT32 BPB parsing**: bytes/sector, sectors/cluster, reserved sectors, #FATs, sectors/FAT, root cluster
- **FAT chain walking**: resolve cluster chains from the primary FAT
- **Directory entry parsing**: 8.3 names, sizes, first cluster, dates; **deleted-file hints** (`0xE5`)
- **Active-file recovery**: reconstruct file body by concatenating FAT-chain clusters
- **Raw/unallocated grep**: locate byte patterns anywhere in the image
- **Hash calculation**: MD5 / SHA1 / SHA256
- **JSON report output**

## Documented Synthetic Fixture Format

`tests/fixtures/disk.img` is a synthetic 8 MiB disk image:

| Region | Content |
|--------|---------|
| LBA 0 | MBR, one active FAT32-LBA partition (type 0x0C) at LBA 2048 |
| LBA 2048 | FAT32 BPB (reserved=32, FATs=2, FAT size=8, root cluster=2) + boot code |
| after | FAT1 + FAT2, then root cluster (2), then data region |
| root cluster | `README.TXT` (live, cluster 3), `DOCUME.TXT` (live), `HIDDEN.BIN` (deleted), `GONE.DAT` (deleted) |
| cluster 3 | README.TXT body |
| offset `0x1000` | `SALVAGEME_FORENSIC_MARKER` (recoverable/unallocated grep target) |

Regenerate with `python3 tests/generate_fixtures.py`.

## Quick Start

```bash
# Analyze the bundled synthetic disk image
python3 cli.py --demo

# Analyze any disk image you own
python3 cli.py --image /path/to/disk.img --output reports/report.json

# Grep the raw image for a byte pattern
python3 cli.py --image /path/to/disk.img --grep "PATTERN"
```

## Testing

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. Run `python3 cli.py --demo` — should exit 0, print MBR + FAT32 files, mark 2 deleted files, recover README body
2. Run `python3 -m unittest discover -s tests` — all tests pass
3. Verify `reports/d2_report.json` contains partition table, BPB, root dir, raw grep hits

## Metrics

- Formats parsed: MBR, GPT (struct), FAT32 BPB, FAT chain, directory entries
- Deleted-file detection: `0xE5` marker
- Test count: 19
- Demo exit code: 0

## License

MIT License — see [LICENSE](LICENSE).
