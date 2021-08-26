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
from os.path import isdir, isfile, join, basename
from pathlib import Path


start_folder = "/mnt/c/"; assert isdir(start_folder)
dst_folder = '/mnt/c/goodware2021/dlls'; assert isdir(dst_folder)
exe_files_json = 'dll_files.json'


def create_exe_json():
    exe_files = list()
    for root, dirs, files in os.walk(start_folder, topdown=False):
        for name in files:
            if name.endswith(('dll', 'DLL')):
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
        exe = exe.replace('C:\\', '/mnt/c/').replace('\\', '/')
        sha256 = get_file_sha256sum(exe)
        file_magic = magic.from_file(exe)
        if '.Net' in file_magic:
            dst_file_sha256 = join(join(dst_folder, 'dotNet'), sha256)
        elif 'Installer' in file_magic or 'ARM' in file_magic:
            return False
        else:
            dst_file_sha256 = join(join(dst_folder, 'native'), sha256)
        if isfile(dst_file_sha256): return False
        shutil.copyfile(exe, dst_file_sha256)
        print(dst_file_sha256)
        return True
    except:
        return None


def taskdll(exe: str) -> Optional[bool]:
    try:
        dst_file_sha256 = join(dst_folder, f'{basename(exe)}_{get_file_sha256sum(exe)}')
        if isfile(dst_file_sha256): return False
        shutil.copyfile(exe, dst_file_sha256)
        print(dst_file_sha256)
        return True
    except:
        return None


def main():
    if not isfile(exe_files_json):
        print('> Start creating json')
        create_exe_json()
        print('< End creating json')

    with open(exe_files_json, 'r') as fp:
        exe_files = json.load(fp)
    print('> json loaded, starting copy')
    with Pool(processes=4) as pool:
        results = list(tqdm(pool.imap(taskdll, exe_files), total=len(exe_files)))

    print(Counter(results))


if __name__ == '__main__':
    main()
