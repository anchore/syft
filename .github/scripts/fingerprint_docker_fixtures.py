#!/usr/bin/env python3

import os
import subprocess
import hashlib

BOLD = '\033[1m'
YELLOW = '\033[0;33m'
RESET = '\033[0m'


def print_message(message):
    print(f"{YELLOW}{message}{RESET}")


def sha256sum(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def is_git_tracked_or_untracked(directory):
    """Returns a sorted list of files in the directory that are tracked or not ignored by Git."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=directory,
        stdout=subprocess.PIPE,
        text=True
    )
    return sorted(result.stdout.strip().splitlines())


def find_test_fixture_dirs_with_images(base_dir):
    """Find directories that contain 'test-fixtures' and at least one 'image-*' directory."""
    for root, dirs, files in os.walk(base_dir):
        if 'test-fixtures' in root:
            image_dirs = [d for d in dirs if d.startswith('image-')]
            if image_dirs:
                yield os.path.realpath(root)


def generate_fingerprints():
    print_message("creating fingerprint files for docker fixtures...")

    for test_fixture_dir in find_test_fixture_dirs_with_images('.'):
        cache_fingerprint_path = os.path.join(test_fixture_dir, 'cache.fingerprint')

        with open(cache_fingerprint_path, 'w') as fingerprint_file:
            for image_dir in find_image_dirs(test_fixture_dir):
                for file in is_git_tracked_or_untracked(image_dir):
                    file_path = os.path.join(image_dir, file)
                    checksum = sha256sum(file_path)
                    path_from_fixture_dir = os.path.relpath(file_path, test_fixture_dir)
                    fingerprint_file.write(f"{checksum}  {path_from_fixture_dir}\n")


def find_image_dirs(test_fixture_dir):
    """Find all 'image-*' directories inside a given test-fixture directory."""
    result = []
    for root, dirs, files in os.walk(test_fixture_dir):
        for dir_name in dirs:
            if dir_name.startswith('image-'):
                result.append(os.path.join(root, dir_name))
    return sorted(result)


if __name__ == "__main__":
    generate_fingerprints()
