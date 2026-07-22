#!/usr/bin/env bash
# Create a vendored-source archive for downstream (offline) packaging.
#
# Produces dist/syft_<version>_vendored-source.tar.gz containing the full syft
# source tree plus a vendor/ directory of all Go module dependencies, so
# downstream packagers can build syft without network access:
#
#     tar -xzf syft_<version>_vendored-source.tar.gz
#     cd syft-<version>
#     go build -mod=vendor ./cmd/syft
#
# This is invoked as a goreleaser global "before" hook (see .goreleaser.yaml) and
# the resulting archive is attached to the GitHub release via release.extra_files.
#
# Vendoring is skipped for snapshot builds to keep the frequent snapshot CI fast.
# The vendor/ directory is removed again once the archive is written so the actual
# goreleaser build runs in module mode exactly as it does today (no behavior change
# to the produced binaries).
set -euo pipefail

VERSION="${1:?usage: create-vendored-source-archive.sh <version> <is-snapshot>}"
IS_SNAPSHOT="${2:-false}"

if [ "${IS_SNAPSHOT}" = "true" ]; then
  echo "skipping vendored-source archive for snapshot build"
  exit 0
fi

DIST_DIR="${DIST_DIR:-dist}"
PREFIX="syft-${VERSION}"
ARCHIVE="${DIST_DIR}/syft_${VERSION}_vendored-source.tar.gz"

mkdir -p "${DIST_DIR}"

echo "vendoring Go module dependencies..."
go mod vendor

# pin the archive mtime to the release commit for a reproducible artifact, mirroring
# the mod_timestamp={{ .CommitTimestamp }} approach used by the goreleaser builds.
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"

# Archive the git-tracked source files plus the (untracked) vendor/ tree, remapped
# under a single top-level ${PREFIX}/ directory so extraction is self-contained.
# Requires GNU tar (the release runs on a Linux runner); --sort/--mtime/--owner keep
# the output byte-for-byte reproducible.
FILE_LIST="$(mktemp)"
trap 'rm -f "${FILE_LIST}"' EXIT
{ git ls-files; find vendor -type f; } | LC_ALL=C sort -u >"${FILE_LIST}"

echo "creating ${ARCHIVE}..."
tar \
  --owner=0 --group=0 --numeric-owner \
  --mtime="@${SOURCE_DATE_EPOCH}" \
  --sort=name \
  --transform "s,^,${PREFIX}/," \
  -czf "${ARCHIVE}" \
  -T "${FILE_LIST}"

# restore the working tree to module mode so goreleaser builds exactly as before
rm -rf vendor

echo "created ${ARCHIVE} ($(du -h "${ARCHIVE}" | cut -f1))"
