#!/usr/bin/python3
import argparse
import hashlib
import os
import magic
import shutil
import sys

from os.path import isdir, isfile, join


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


def main(start_folder: str, dst_folder: str, remove_not_matching: bool):
    for root, dirs, files in os.walk(start_folder, topdown=False):
        print('>>>', root)
        for name in files:
            file_path = join(root, name)
            file_magic = None
            if is_pe(file_path):
                file_magic = magic.from_file(file_path)
                if pe_filter(file_magic):
                    if dst_folder is not None:
                        try:
                            dst_file_sha256 = join(dst_folder, f'{get_file_sha256sum(file_path)}')
                            if not isfile(dst_file_sha256):
                                shutil.copyfile(file_path, dst_file_sha256)
                                print(f'[{file_magic}] {file_path} -> {dst_file_sha256}')
                        except Exception as e:
                            print(f'[{file_magic}] {file_path} !!!', file=sys.stderr)
                            print(e, file=sys.stderr)
                    continue
            if remove_not_matching:
                print(f'[{file_magic}] {file_path} -> /dev/null')
                os.remove(file_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='pypefilter.py filters out non-native Portable Executable files')
    parser.add_argument('-s', '--src', help='Source directory', type=str, required=True)
    parser.add_argument('-d', '--dst', help='Destination directory', type=str)
    parser.add_argument('--delete', help='Delete non-matching files', action='store_true')
    args = parser.parse_args()
    assert isdir(args.src)
    if args.dst is not None:
        assert isdir(args.dst)

    main(args.src, args.dst, args.delete)
