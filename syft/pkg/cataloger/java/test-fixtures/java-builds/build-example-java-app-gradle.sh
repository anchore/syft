#!/usr/bin/env bash
set -uxe

# note: this can be easily done in a 1-liner, however circle CI does NOT allow volume mounts from the host in docker executors (since they are on remote hosts, where the host files are inaccessible)

PKGSDIR=$1
CTRID=$(docker create -u "$(id -u):$(id -g)" -v /example-java-app -w /example-java-app gradle:6.8.3-jdk gradle build)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

docker cp "$(pwd)/example-java-app" "${CTRID}:/"
docker start -a "${CTRID}"
mkdir -p "$PKGSDIR"
docker cp "${CTRID}:/example-java-app/build/libs/example-java-app-gradle-0.1.0.jar" "$PKGSDIR"
