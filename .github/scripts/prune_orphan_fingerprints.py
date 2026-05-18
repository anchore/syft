#!/usr/bin/env python3
"""
Remove orphan *.fingerprint files left behind by moved/deleted catalogers.

A fingerprint is considered orphaned when:
  1. its paired content path (the fingerprint path with `.fingerprint` stripped)
     does not exist, AND
  2. the nearest ancestor `testdata/` directory has no `Makefile` claiming
     responsibility for generating that path.

The second condition is the safety check: if there is a Makefile, the
fingerprint is "live" and might just be waiting for fixtures to be built —
leave it alone. Without a Makefile, nothing in-repo will ever regenerate
the content, so the fingerprint is dead weight that triggers spurious
"missing path" warnings.

Empty parent directories are also pruned after removing the fingerprint.

Use --dry-run to preview without deleting.
"""
from __future__ import annotations

import argparse
import glob
import os
import sys


def find_ancestor_testdata(path: str) -> str | None:
    d = os.path.dirname(path)
    while d and d not in (".", os.sep):
        if os.path.basename(d) == "testdata":
            return d
        d = os.path.dirname(d)
    return None


def is_orphan(fingerprint: str) -> bool:
    paired = fingerprint[: -len(".fingerprint")]
    if os.path.exists(paired):
        return False

    testdata_dir = find_ancestor_testdata(fingerprint)
    if testdata_dir and os.path.isfile(os.path.join(testdata_dir, "Makefile")):
        # a Makefile exists that may regenerate this — not safe to prune
        return False

    return True


def prune_empty_parents(start: str, stop_at: str = ".") -> list[str]:
    removed = []
    d = os.path.dirname(start)
    stop_at = os.path.abspath(stop_at)
    while d and os.path.abspath(d) != stop_at:
        try:
            if not os.listdir(d):
                os.rmdir(d)
                removed.append(d)
                d = os.path.dirname(d)
            else:
                break
        except OSError:
            break
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be removed without deleting anything",
    )
    args = parser.parse_args()

    all_fingerprints = glob.glob("**/test*/**/*.fingerprint", recursive=True)
    orphans = sorted(fp for fp in all_fingerprints if is_orphan(fp))

    if not orphans:
        print("no orphan fingerprints found")
        return 0

    verb = "would remove" if args.dry_run else "removing"
    print(f"{verb} {len(orphans)} orphan fingerprint(s):")
    for fp in orphans:
        print(f"- {fp}")
        if args.dry_run:
            continue
        try:
            os.remove(fp)
        except OSError as e:
            print(f"  ! failed to remove: {e}", file=sys.stderr)
            continue
        for d in prune_empty_parents(fp):
            print(f"  (also removed empty dir {d})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
