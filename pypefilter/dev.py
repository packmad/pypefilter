#!/usr/bin/python3
import argparse
import hashlib
import json
import os
import magic  # pip3 install python-magic
import shutil
import sys

from multiprocessing import Pool, freeze_support
from itertools import repeat
from os.path import isdir, isfile, join
from pathlib import Path


start_folder = "/mnt/c"
assert isdir(start_folder)

exe_files_json = 'exe_files.json'

if not isfile(exe_files_json):
    exe_files = list()

    for root, dirs, files in os.walk(start_folder, topdown=False):
        for name in files:
            if name.endswith('exe') or name.endswith('EXE'):
                exe_files.append(join(root, name))

    with open(exe_files_json, 'w') as fp:
        json.dump(exe_files, fp)

with open(exe_files_json, 'r') as fp:
    exe_files = json.load(fp)

for exe in exe_files:
    with open(exe, 'rb') as fp:
        assert fp.read(2) == b'MZ'
