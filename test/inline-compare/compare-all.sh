#!/usr/bin/env bash
set -eu

# TODO: Add "alpine:3.12.0" back in when we've figured out how to handle the apk version field w/ and w/o release information
images=("debian:10.5" "centos:8.2.2004")

# gather all image analyses
for img in "${images[@]}"; do
    echo "Gathering facts for $img"
    COMPARE_IMAGE=${img} make gather-image
done

# compare all results
for img in "${images[@]}"; do
    echo "Comparing results for $img"
    COMPARE_IMAGE=${img} make compare-image
done
