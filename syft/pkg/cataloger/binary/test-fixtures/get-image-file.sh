#!/usr/bin/env bash
set -uxe

CTRID=$(docker create $1)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

mkdir -p $(dirname $3)

docker cp ${CTRID}:$2 $3
