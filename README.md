> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# D2 — Disk Image Analyzer

D2 is a **disk forensics** engine that hand-parses **MBR/GPT partitions**, FAT32
filesystem metadata, and directory entries to recover files, spot **deleted
data**, and grep raw disk space for artifacts.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/d2-disk-analyzer)](https://github.com/5h4d0wn1k/d2-disk-analyzer)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/d2-disk-analyzer)](https://github.com/5h4d0wn1k/d2-disk-analyzer)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/d2-disk-analyzer)](https://github.com/5h4d0wn1k/d2-disk-analyzer)

## Why D2

Deleted files are where the evidence lives — but raw disk images hide them
behind partition tables, file systems, and FAT chains. D2 is a **digital
forensics** learning tool that does the parsing by hand (no heavy libraries):
structure-level MBR/GPT reads, FAT32 BPB decode, FAT-chain walking, and
directory-entry recovery that surfaces deleted entries via their `0xE5`
marker. Everything runs offline against a synthetic disk image, making it a
safe way to learn **file carving** and data-recovery workflows in the lab.

## Features

- **MBR partition parsing** — status, type, LBA start, sector count, size
- **GPT partition parsing** — type GUIDs, names, LBA ranges
- **FAT32 BPB decoding** — bytes/sector, sectors/cluster, FAT sizing, root cluster
- **FAT-chain walking** — resolve full cluster chains from the primary FAT
- **Directory entry parsing** — 8.3 names, sizes, first cluster, dates
- **Deleted-file hints** — `0xE5` markers on removed entries
- **Active-file recovery** — rebuild file bodies from chained clusters
- **Raw/unallocated grep** — locate byte patterns anywhere in the image
- **Hashing** — MD5, SHA1, SHA256 + JSON report export

## Quickstart

```bash
# Analyze the bundled synthetic 8 MiB disk image
python3 cli.py --demo

# Analyze any disk image you own
python3 cli.py --image /path/to/disk.img --output reports/report.json

# Grep raw image for an artifact pattern
python3 cli.py --image /path/to/disk.img --grep "SALVAGEME_FORENSIC_MARKER"

# Tests
python3 -m unittest discover -s tests
```

## Examples

- `tests/fixtures/disk.img` — synthetic 8 MiB image (MBR + one FAT32 partition) with live and deleted files, plus a recoverable marker at offset `0x1000`
- Regenerate with `python3 tests/generate_fixtures.py`

## Project structure

- `cli.py` — CLI entrypoint
- `firmware/disk_analyzer.py` — partition/file-system parsing engine
- `tests/` — fixture generator and round-trip tests

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)