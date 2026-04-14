#!/usr/bin/env bash
set -uxe

PKGSDIR=$1

curl https://raw.githubusercontent.com/blacktop/go-macho/master/internal/testdata/gcc-amd64-darwin-exec-debug.base64 |
  base64 -d > $PKGSDIR/gcc-amd64-darwin-exec-debug
