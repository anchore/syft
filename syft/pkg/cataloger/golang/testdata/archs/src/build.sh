#!/usr/bin/env bash
set -ue

# note: this can be easily done in a 1-liner, however circle CI does NOT allow volume mounts from the host in docker executors (since they are on remote hosts, where the host files are inaccessible)
# note: gocache override is so we can run docker build not as root in a container without permission issues

BINARY=$1

mkdir -p "$(dirname "$BINARY")"

CTRID=$(docker create -e GOOS="${GOOS}" -e GOARCH="${GOARCH}" -u "$(id -u):$(id -g)" -e GOCACHE=/tmp -w /src golang:1.17 go build -o main main.go)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

# note: pwd = parent directory (archs)
docker cp "$(pwd)/src" "${CTRID}:/"
docker start -a "${CTRID}"
docker cp "${CTRID}:/src/main" "$BINARY"
