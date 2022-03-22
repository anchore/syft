#!/usr/bin/env bash
set -eux

# $1 —— absolute path to destination file, should end with .zip, ideally
# $2 —— absolute path to directory from which to add entries to the archive

pushd "$2" && find . -print | zip "$1" -@ && popd
