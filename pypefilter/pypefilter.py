#!/usr/bin/python3
import argparse
import hashlib
import os
from typing import Optional
from collections import Counter

import magic  # pip3 install python-magic
import shutil
import sys

from multiprocessing import Pool, freeze_support
from os.path import isdir, isfile, join
from pathlib import Path
from tqdm import tqdm  # pip3 install tqdm


DELETE: bool = False
RENAME: bool = False
VERBOSE: bool = False
VERBOSE_MAGIC: bool = False
DST_FOLDER: Optional[str] = None
BLACKLIST = ['DLL', '.Net', 'Installer', 'ARM']


def vprint(action: str, fmagic: str, src: str, dst: str):
    if VERBOSE:
        if VERBOSE_MAGIC and fmagic is None:
            fmagic = magic.from_file(src)
        print(f'[{action}][{fmagic}] {src} -> {dst}')


def get_file_sha256sum(file_path: str) -> str:
    hash_function = hashlib.sha256()
    with open(file_path, 'rb', buffering=0) as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_function.update(chunk)
    return hash_function.hexdigest()


def is_pe(file_path: str) -> bool:
    try:
        return open(file_path, 'rb').read(2) == b'MZ'
    except Exception:
        return False


def check(file_path: str):
    file_magic = None
    is_native_pe = False
    if is_pe(file_path):
        file_magic = magic.from_file(file_path)
        if file_magic.startswith('PE32') and not any(x in file_magic for x in BLACKLIST):
            is_native_pe = True
            if RENAME or DST_FOLDER is not None:
                file_sha256sum = get_file_sha256sum(file_path)
                if DST_FOLDER is not None:
                    try:
                        dst_file_sha256 = join(DST_FOLDER, f'{file_sha256sum}')
                        if not isfile(dst_file_sha256):
                            shutil.copyfile(file_path, dst_file_sha256)
                            vprint('C', file_magic, file_path, dst_file_sha256)
                    except Exception as e:
                        print(f'[!][{file_magic}] {file_path}', file=sys.stderr)
                        print(e, file=sys.stderr)
                if RENAME:
                    dst_path = join(Path(file_path).parent, file_sha256sum)
                    if file_path != dst_path:
                        vprint('R', file_magic, file_path, dst_path)
                        os.rename(file_path, dst_path)
    if DELETE and not is_native_pe:
        vprint('X', file_magic, file_path, '/dev/null')
        os.remove(file_path)
    return file_magic


def parallel_filter(start_folder: str, dst_folder: str):
    with Pool(processes=4) as pool:
        for root, dirs, files in os.walk(start_folder, topdown=False):
            print('>>>', root)
            r = list(tqdm(pool.imap(check, [join(root, f) for f in files]), total=len(files)))
            print(Counter(r))
            print('<<<', root)


def main():
    global BLACKLIST, VERBOSE, VERBOSE_MAGIC, DELETE, RENAME, DST_FOLDER
    freeze_support()
    parser = argparse.ArgumentParser(
        description='PyPEfilter filters out non-native Portable Executable files')
    parser.add_argument('-s', '--src', type=str, help='Source directory', required=True)
    parser.add_argument('-d', '--dst', type=str, help='Destination directory')
    parser.add_argument('--rename', help='Rename matching files with their sha256 hash',
                        action='store_true')
    parser.add_argument('--delete', help='Delete non-matching files', action='store_true')
    parser.add_argument('--no64', help='Exclude PE for the 64bit arch', action='store_true')
    me_group = parser.add_mutually_exclusive_group()
    me_group.add_argument('-v', '--verbose', help='Display messages', action='store_true')
    me_group.add_argument('-vm', '--vmagic',
                          help='Display messages and magic of non-matching files',
                          action='store_true')
    args = parser.parse_args()
    assert isdir(args.src)
    if args.dst is not None:
        assert isdir(args.dst)
    if args.dst is None and not args.delete and not args.rename:
        sys.exit('You are not copying|renaming|deleting... save energy!')
    if args.no64:
        BLACKLIST.append('x86-64')
    VERBOSE = args.verbose or args.vmagic
    VERBOSE_MAGIC = args.vmagic
    DELETE = args.delete
    RENAME = args.rename
    DST_FOLDER = args.dst
    parallel_filter(args.src)


if __name__ == '__main__':
    main()
