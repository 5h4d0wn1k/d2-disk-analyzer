# D2 — Disk Image Analyzer

Reads MBR/GPT partitions, extracts file metadata, recovers deleted files, timeline analysis.

## Overview

This project implements a disk image forensics analyzer that:
- Parses MBR and GPT partition tables
- Detects filesystem types (NTFS, FAT32, ext2)
- Extracts file metadata from partition structures
- Scans for deleted file signatures across the image
- Builds forensic timelines from timestamps
- Calculates file hashes for integrity verification

## Features

- **Partition parsing**: MBR and GPT partition table support
- **Filesystem detection**: NTFS, FAT32, exFAT, ext2 recognition
- **File extraction**: Directory entry parsing for metadata
- **Deleted recovery**: Signature-based scanning for deleted files
- **Timeline analysis**: Timestamp extraction and ordering
- **Hash verification**: MD5, SHA1, SHA256 calculation
- **Test mode**: Generate synthetic test disk images

## Installation

```bash
# No external dependencies required
```

## Usage

```bash
# Full analysis
python3 disk_analyzer.py --image disk.raw

# Generate test image and analyze
python3 disk_analyzer.py --generate-test test_disk.raw

# Parse MBR only
python3 disk_analyzer.py --image disk.raw --mbr

# Parse GPT only
python3 disk_analyzer.py --image disk.raw --gpt

# Calculate hashes only
python3 disk_analyzer.py --image disk.raw --hash

# Export to JSON
python3 disk_analyzer.py --image disk.raw --output report.json
```

## Example Output

```
============================================================
  D2 — Disk Image Analyzer — Analysis Report
============================================================
  File: disk.raw
  Size: 2,097,152 bytes
  MD5:  b2c3d4e5f6a7...

  Partition Scheme: MBR
    Partition 1: NTFS/exFAT/HPFS (1024.0 MB)
    Partition 2: Linux filesystem (512.0 MB)

  Active Files: 3
  Deleted Files Found: 2
  Deleted File Signatures: 5

  --- Deleted File Signatures ---
    0x00010000: PNG image
    0x00020000: JPEG image
    0x00030000: PDF document

  Timeline: 5 events
    2024-01-15 10:00:00 file_created: DOCUMENT.TXT
============================================================
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the disk/system owner before using this tool
- Unauthorized access to computer storage is illegal under federal and state laws
- This tool should ONLY be used on disks/images you own or have written authorization to analyze

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Federal Rules of Evidence**: Evidence obtained without authorization may be inadmissible
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Disk images may contain personal data subject to privacy regulations

### Acceptable Use
- Forensic analysis of your own systems during incident response
- Authorized digital forensics investigations with proper legal authority
- Academic research in controlled lab environments
- Security education and training with synthetic test data

### Prohibited Use
- Analyzing disk images from systems without authorization
- Recovering personal data without legal authority
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
