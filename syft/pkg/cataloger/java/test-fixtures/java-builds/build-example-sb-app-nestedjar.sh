#!/usr/bin/env bash
set -uxe

# note: this can be easily done in a 1-liner, however circle CI does NOT allow volume mounts from the host in docker executors (since they are on remote hosts, where the host files are inaccessible)

PKGSDIR=$1
CTRID=$(docker create -u "$(id -u):$(id -g)" -e MAVEN_CONFIG=/tmp/.m2 -v /example-sb-app -w /example-sb-app maven:3.8.6-openjdk-18 mvn -Duser.home=/tmp -DskipTests package spring-boot:repackage)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

docker cp "$(pwd)/example-sb-app" "${CTRID}:/"
docker start -a "${CTRID}"
mkdir -p "$PKGSDIR"
docker cp "${CTRID}:/example-sb-app/target/spring-boot-0.0.1-SNAPSHOT.jar" "$PKGSDIR"
