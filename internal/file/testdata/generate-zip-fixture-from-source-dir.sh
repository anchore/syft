#!/usr/bin/env bash
set -eux

# $1 —— absolute path to destination file, should end with .zip, ideally
# $2 —— absolute path to directory from which to add entries to the archive
# $3 —— if files should be zip64 or not

if [[$3]]; then
	pushd "$2" && find . -print | zip -fz "$1" -@ && popd
else
	pushd "$2" && find . -print | zip "$1" -@ && popd
fi
