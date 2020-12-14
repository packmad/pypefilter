## PyPEfilter

```
$ ./pypefilter.py --help
usage: pypefilter.py [-h] -s SRC [-d DST] [--rename] [--delete] [-v | -vm]

PyPEfilter filters out non-native Portable Executable files

optional arguments:
  -h, --help         show this help message and exit
  -s SRC, --src SRC  Source directory
  -d DST, --dst DST  Destination directory
  --rename           Rename matching files with their sha256 hash
  --delete           Delete non-matching files
  -v, --verbose      Display messages
  -vm, --vmagic      Display messages and magic of non-matching files
```

PyPEfilter filters out non-native (DLLs, .Net, Installer, ...) Portable Executable files from `--src` directory.

If `--dst` directory is provided, it copies all the matching PE files from `--src` to `--dst`, and renames the files in the destination directory with their sha256 hash.

Specifying:
*  `--rename`: it renames the matching PE files in `--src` with their sha256 hash
*  `--delete`: it deletes the non-matching PE files from `--src`


### Disclaimer
This script is based on [python-magic](https://pypi.org/project/python-magic/), a Python interface to the libmagic file type identification library.
Therefore, for example, it does not identify all types of installers.
