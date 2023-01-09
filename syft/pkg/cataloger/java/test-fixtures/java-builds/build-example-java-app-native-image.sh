#!/usr/bin/env bash
set -uxe

PKGSDIR=$1

CTRID=$(docker create -v /example-java-app ghcr.io/graalvm/native-image:22.2.0 -cp /example-java-app/example-java-app-maven-0.1.0.jar --no-fallback -H:Class=hello.HelloWorld -H:Name=example-java-app)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

docker cp "${PKGSDIR}/example-java-app-maven-0.1.0.jar" "${CTRID}:/example-java-app/"

docker start -a "${CTRID}"
docker cp "${CTRID}:/app/example-java-app" $PKGSDIR
