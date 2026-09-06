#!/usr/bin/env python3
"""CLI entry point for D2 Disk Analyzer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "firmware"))
from disk_analyzer import main

if __name__ == "__main__":
    main()
