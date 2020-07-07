#!/usr/bin/env bash
set -uxe

# note: this can be easily done in a 1-liner, however circle CI does NOT allow volume mounts from the host in docker executors (since they are on remote hosts, where the host files are inaccessible)

CTRID=$(docker create -u "$(id -u):$(id -g)" -v /example-app -w /example-app gradle:jdk gradle build)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

docker cp "$(pwd)/example-app" "${CTRID}:/"
docker start -a "${CTRID}"
mkdir -p packages
docker cp "${CTRID}:/example-app/build/libs/example-app-gradle-0.1.0.jar" packages/