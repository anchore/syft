#!/usr/bin/env bash
set -uxe

# note: this can be easily done in a 1-liner, however circle CI does NOT allow volume mounts from the host in docker executors (since they are on remote hosts, where the host files are inaccessible)

CTRID=$(docker create -u "$(id -u):$(id -g)" -e MAVEN_CONFIG=/tmp/.m2 -v /example-app -w /example-app maven:openjdk mvn -Duser.home=/tmp -DskipTests package)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

docker cp "$(pwd)/example-app" "${CTRID}:/"
docker start -a "${CTRID}"
mkdir -p packages
docker cp "${CTRID}:/example-app/target/example-app-maven-0.1.0.jar" packages/