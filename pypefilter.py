#!/usr/bin/python3
import argparse
import hashlib
import os
import magic  # pip3 install python-magic
import shutil
import sys

from multiprocessing import Pool, freeze_support
from itertools import repeat
from os.path import isdir, isfile, join
from pathlib import Path


VERBOSE = False


def vprint(msg: str):
    if VERBOSE:
        print(msg)


def get_file_sha256sum(file_path: str) -> str:
    hash_function = hashlib.sha256()
    with open(file_path, 'rb', buffering=0) as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_function.update(chunk)
    return hash_function.hexdigest()


def is_pe(file_path: str) -> bool:
    try:
        return isfile(file_path) and open(file_path, 'rb').read(2) == b'MZ'
    except Exception:
        return False


def pe_filter(pe_magic: str) -> bool:
    return pe_magic.startswith('PE32') and not any(x in pe_magic for x in ['DLL', '.Net', 'Installer', 'ARM'])


def check(file_path: str, dst_folder: str, remove_not_matching: bool, rename: bool):
    file_magic = None
    if is_pe(file_path):
        file_magic = magic.from_file(file_path)
        if pe_filter(file_magic):
            file_sha256sum = get_file_sha256sum(file_path)
            if dst_folder is not None:
                try:
                    dst_file_sha256 = join(dst_folder, f'{file_sha256sum}')
                    if not isfile(dst_file_sha256):
                        shutil.copyfile(file_path, dst_file_sha256)
                        vprint(f'[C][{file_magic}] {file_path} -> {dst_file_sha256}')
                except Exception as e:
                    print(f'[!][{file_magic}] {file_path}', file=sys.stderr)
                    print(e, file=sys.stderr)
            if rename:
                dst_path = join(Path(file_path).parent, file_sha256sum)
                vprint(f'[R][{file_magic}] {file_path} -> {dst_path}')
                os.rename(file_path, dst_path)
            return
    if remove_not_matching:
        vprint(f'[X][{file_magic}] {file_path} -> /dev/null')
        os.remove(file_path)


def main(start_folder: str, dst_folder: str, delete: bool, rename: bool):
    with Pool() as pool:
        for root, dirs, files in os.walk(start_folder, topdown=False):
            print('>>>', root)
            pool.starmap(check,
                         zip([join(root, name) for name in files], repeat(dst_folder), repeat(delete), repeat(rename)))
            print('<<<', root)


if __name__ == '__main__':
    freeze_support()
    parser = argparse.ArgumentParser(description='pypefilter.py filters out non-native Portable Executable files')
    parser.add_argument('-s', '--src', help='Source directory', type=str, required=True)
    parser.add_argument('-d', '--dst', help='Destination directory', type=str)
    parser.add_argument('--rename', help='Rename matching files with their sha256 hash', action='store_true')
    parser.add_argument('--delete', help='Delete non-matching files', action='store_true')
    parser.add_argument('-v', '--verbose', help='Display messages', action='store_true')
    args = parser.parse_args()
    assert isdir(args.src)
    if args.dst is not None:
        assert isdir(args.dst)
    if args.dst is None and not args.delete and not args.rename:
        sys.exit('You are not copying|renaming|deleting... save energy!')
    VERBOSE = args.verbose
    main(args.src, args.dst, args.delete, args.rename)
