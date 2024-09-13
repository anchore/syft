#!/usr/bin/env python3
from __future__ import annotations

import os
import glob
import sys
import json
import hashlib


IGNORED_PREFIXES = []


def find_fingerprints_and_check_dirs(base_dir):
    all_fingerprints = set(glob.glob(os.path.join(base_dir, '**', 'test*', '**', '*.fingerprint'), recursive=True))

    all_fingerprints = {os.path.relpath(fp) for fp in all_fingerprints
                        if not any(fp.startswith(prefix) for prefix in IGNORED_PREFIXES)}

    if not all_fingerprints:
        show("No .fingerprint files or cache directories found.")
        exit(1)

    missing_content = []
    valid_paths = set()
    fingerprint_contents = []

    for fingerprint in all_fingerprints:
        path = fingerprint.replace('.fingerprint', '')

        if not os.path.exists(path):
            missing_content.append(path)
            continue

        if not os.path.isdir(path):
            valid_paths.add(path)
            continue

        if os.listdir(path):
            valid_paths.add(path)
        else:
            missing_content.append(path)

        with open(fingerprint, 'r') as f:
            content = f.read().strip()
            fingerprint_contents.append((fingerprint, content))

    return sorted(valid_paths), missing_content, fingerprint_contents


def parse_fingerprint_contents(fingerprint_content):
    input_map = {}
    for line in fingerprint_content.splitlines():
        digest, path = line.split()
        input_map[path] = digest
    return input_map


def calculate_sha256(fingerprint_contents):
    sorted_fingerprint_contents = sorted(fingerprint_contents, key=lambda x: x[0])

    concatenated_contents = ''.join(content for _, content in sorted_fingerprint_contents)

    sha256_hash = hashlib.sha256(concatenated_contents.encode()).hexdigest()

    return sha256_hash


def calculate_file_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def show(*s: str):
    print(*s, file=sys.stderr)


def main(file_path: str | None):
    base_dir = '.'
    valid_paths, missing_content, fingerprint_contents = find_fingerprints_and_check_dirs(base_dir)

    if missing_content:
        show("The following paths are missing or have no content, but have corresponding .fingerprint files:")
        for path in sorted(missing_content):
            show(f"- {path}")
        show("Please ensure these paths exist and have content if they are directories.")
        exit(1)

    sha256_hash = calculate_sha256(fingerprint_contents)

    paths_with_digests = []
    for path in sorted(valid_paths):
        fingerprint_file = f"{path}.fingerprint"
        try:
            if os.path.exists(fingerprint_file):
                file_digest = calculate_file_sha256(fingerprint_file)

                # Parse the fingerprint file to get the digest/path tuples
                with open(fingerprint_file, 'r') as f:
                    fingerprint_content = f.read().strip()
                    input_map = parse_fingerprint_contents(fingerprint_content)

                paths_with_digests.append({
                    "path": path,
                    "digest": file_digest,
                    "input": input_map
                })

        except Exception as e:
            show(f"Error processing {fingerprint_file}: {e}")
            raise e


    output = {
        "digest": sha256_hash,
        "paths": paths_with_digests
    }

    content = json.dumps(output, indent=2, sort_keys=True)

    if file_path:
        with open(file_path, 'w') as f:
            f.write(content)

    print(content)


if __name__ == "__main__":
    file_path = None
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    main(file_path)
