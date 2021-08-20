#!/usr/bin/python3
import argparse
import hashlib
import json
import os
import magic  # pip3 install python-magic
import shutil
import sys

from typing import Optional
from collections import Counter
from tqdm import tqdm
from multiprocessing import Pool, freeze_support
from itertools import repeat
from os.path import isdir, isfile, join
from pathlib import Path


start_folder = "/mnt/c"; assert isdir(start_folder)
dst_folder = '/mnt/c/stmp'
exe_files_json = 'exe_files.json'


def create_exe_json():
    exe_files = list()
    for root, dirs, files in os.walk(start_folder, topdown=False):
        for name in files:
            if name.endswith(('exe', 'EXE')):
                exe_files.append(join(root, name))
    with open(exe_files_json, 'w') as fp:
        json.dump(exe_files, fp)


def get_file_sha256sum(file_path: str) -> str:
    hash_function = hashlib.sha256()
    with open(file_path, 'rb', buffering=0) as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_function.update(chunk)
    return hash_function.hexdigest()


def task(exe: str) -> Optional[bool]:
    try:
        sha256 = get_file_sha256sum(exe)
        dst_file_sha256 = join(dst_folder, sha256)
        if isfile(dst_file_sha256): return False
        shutil.copyfile(exe, dst_file_sha256)
        return True
    except:
        return None


def main():
    if not isfile(exe_files_json):
        create_exe_json()

    with open(exe_files_json, 'r') as fp:
        exe_files = json.load(fp)

    with Pool() as pool:
        results = list(tqdm(pool.imap(task, exe_files), total=len(exe_files)))

    print(Counter(results))



if __name__ == '__main__':
    main()
