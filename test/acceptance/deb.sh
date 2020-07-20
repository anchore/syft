#!/usr/bin/env bash
set -eux

DISTDIR=$1
RESULTSDIR=$2
ACC_TEST_IMAGE=$3

apt install ${DISTDIR}/imgbom_*_linux_amd64.deb -y
imgbom version -v
imgbom ${ACC_TEST_IMAGE} -o json > ${RESULTSDIR}/acceptance-deb-${ACC_TEST_IMAGE}.json