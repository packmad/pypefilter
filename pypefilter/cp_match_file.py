#!/usr/bin/env python3

import os
import sys
import shutil
from os.path import isdir, isfile, join, basename, abspath, dirname, realpath
from pathlib import Path
from typing import Optional, Dict


def main(file_list: str, src_dir: str, dst_dir: str):
    with open(file_list) as fp:
        fnames = set(line.strip() for line in fp)
    print('file_list has #', len(fnames), 'entries')

    for root, dirs, files in os.walk(src_dir, topdown=False):
        print('>>>', root)
        for f in files:
            if f in fnames:
                src_file = join(root, f)
                dst_file = join(dst_dir, f)
                shutil.copyfile(src_file, dst_file)
                print(src_file, '->', dst_file)
        print('<<<', root)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit(f'Usage: {basename(__file__)} FILE.list SRC_DIR DST_DIR')
    file_list = sys.argv[1]
    assert isfile(file_list)
    src_dir = sys.argv[2]
    assert isdir(src_dir)
    dst_dir = sys.argv[3]
    assert isdir(dst_dir)
    main(file_list, src_dir, dst_dir)
