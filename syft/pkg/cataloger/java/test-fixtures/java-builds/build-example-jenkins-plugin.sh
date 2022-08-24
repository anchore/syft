#!/usr/bin/env bash
set -uxe

# note: this can be easily done in a 1-liner, however circle CI does NOT allow volume mounts from the host in docker executors (since they are on remote hosts, where the host files are inaccessible)

PKGSDIR=$1
CTRID=$(docker create -u "$(id -u):$(id -g)" -e MAVEN_CONFIG=/tmp/.m2 -v /example-jenkins-plugin -w /example-jenkins-plugin maven:3.8.6-openjdk-18 mvn -Duser.home=/tmp -DskipTests package)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

docker cp "$(pwd)/example-jenkins-plugin" "${CTRID}:/"
docker start -a "${CTRID}"
mkdir -p "$PKGSDIR"
docker cp "${CTRID}:/example-jenkins-plugin/target/example-jenkins-plugin.hpi" "$PKGSDIR"
docker cp "${CTRID}:/example-jenkins-plugin/target/example-jenkins-plugin.jar" "$PKGSDIR"
