## pypefilter

pypefilter.py filters out non-native Portable Executable files from `--src` directory.

If `--dst` directory is provided, it copies all the matching PE files from `--src` to `--dst`, renaming them with their sha256 hash.

Instead, with `--delete` it deletes the non-matching PE files from `--src`
