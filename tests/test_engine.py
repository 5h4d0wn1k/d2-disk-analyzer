#!/usr/bin/env python3
"""Tests for D2 Disk Analyzer."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "firmware"))
from disk_analyzer import DiskAnalyzer, struct

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "disk.img")


class TestLoad(unittest.TestCase):
    def test_load(self):
        da = DiskAnalyzer(FIXTURE)
        self.assertTrue(da.load_image())
        self.assertGreater(da.file_size, 0)


class TestMBR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.da = DiskAnalyzer(FIXTURE)
        cls.da.load_image()
        cls.mbr = cls.da.parse_mbr()

    def test_mbr_type(self):
        self.assertEqual(self.mbr["type"], "MBR")

    def test_partition_fat32(self):
        self.assertEqual(len(self.mbr["partitions"]), 1)
        self.assertEqual(self.mbr["partitions"][0]["type"], "FAT32 LBA")
        self.assertEqual(self.mbr["partitions"][0]["type_hex"], "0x0c")

    def test_partition_lba(self):
        self.assertEqual(self.mbr["partitions"][0]["lba_start"], 2048)

    def test_mbr_signature(self):
        self.assertEqual(self.mbr["signature"], "55aa")


class TestPartitionScheme(unittest.TestCase):
    def test_detect(self):
        da = DiskAnalyzer(FIXTURE)
        da.load_image()
        scheme = da.detect_partition_scheme()
        self.assertEqual(scheme["type"], "MBR")


class TestFAT32BPB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.da = DiskAnalyzer(FIXTURE)
        cls.da.load_image()
        cls.bpb = cls.da.fat32_bpb(2048)

    def test_bpb_parsed(self):
        self.assertIsNotNone(self.bpb)
        self.assertEqual(self.bpb["bytes_per_sector"], 512)
        self.assertEqual(self.bpb["sectors_per_cluster"], 1)
        self.assertEqual(self.bpb["reserved_sectors"], 32)
        self.assertEqual(self.bpb["num_fats"], 2)
        self.assertEqual(self.bpb["root_cluster"], 2)

    def test_fat_entry_values(self):
        fat_start = 2048 + self.bpb["reserved_sectors"]
        self.assertEqual(self.da.fat32_fat_entry(self.bpb, fat_start, 0), 0x0FFFFFF8)
        self.assertEqual(self.da.fat32_fat_entry(self.bpb, fat_start, 2), 0x0FFFFFFF)
        self.assertEqual(self.da.fat32_fat_entry(self.bpb, fat_start, 3), 0x0FFFFFFF)


class TestFAT32Directory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.da = DiskAnalyzer(FIXTURE)
        cls.da.load_image()
        cls.bpb = cls.da.fat32_bpb(2048)
        cls.fs = cls.da.fat32_parse_root(cls.bpb, 2048)

    def test_active_files(self):
        names = [f["name"] for f in self.fs["active"]]
        self.assertIn("README.TXT", names)
        self.assertIn("DOCUME.TXT", names)

    def test_deleted_hints(self):
        names = [f["name"] for f in self.fs["deleted"]]
        self.assertIn("HIDDEN.BIN", names)
        self.assertIn("GONE.DAT", names)

    def test_readme_chain(self):
        readme = [f for f in self.fs["all"] if f["name"] == "README.TXT"][0]
        self.assertEqual(readme["chain"], [3])

    def test_readme_body_recover(self):
        body = self.da.fat32_recover(self.bpb, 2048, self.fs, "README.TXT")
        self.assertIsNotNone(body)
        self.assertTrue(body.startswith(b"Hello forensic investigator"))

    def test_readme_size(self):
        readme = [f for f in self.fs["all"] if f["name"] == "README.TXT"][0]
        self.assertEqual(readme["size"], 61)


class TestRawGrep(unittest.TestCase):
    def test_marker_found(self):
        da = DiskAnalyzer(FIXTURE)
        da.load_image()
        hits = da.raw_grep(b"SALVAGEME_FORENSIC_MARKER")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0], 0x1000)


class TestHashes(unittest.TestCase):
    def test_hashes(self):
        da = DiskAnalyzer(FIXTURE)
        da.load_image()
        h = da.calculate_hashes()
        self.assertEqual(len(h["md5"]), 32)
        self.assertEqual(len(h["sha256"]), 64)


class TestFullAnalysis(unittest.TestCase):
    def test_full(self):
        da = DiskAnalyzer(FIXTURE)
        da.load_image()
        r = da.full_analysis()
        self.assertEqual(r["filesystem"], "FAT32")
        self.assertEqual(r["partition_scheme"]["type"], "MBR")
        self.assertEqual(len(r["root_dir"]["deleted"]), 2)
        self.assertEqual(len(r["raw_grep"]), 1)


class TestCLIHelp(unittest.TestCase):
    def test_help_exits_zero(self):
        import subprocess
        cli = os.path.join(os.path.dirname(__file__), "..", "cli.py")
        r = subprocess.run([sys.executable, cli, "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


class TestCLIDemo(unittest.TestCase):
    def test_demo_exits_zero(self):
        import subprocess
        cli = os.path.join(os.path.dirname(__file__), "..", "cli.py")
        r = subprocess.run([sys.executable, cli, "--demo"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("FAT32", r.stdout)
        self.assertIn("[DEL]", r.stdout)


if __name__ == "__main__":
    unittest.main()
