#!/usr/bin/env bash
set -eux

DISTDIR=$1
RESULTSDIR=$2
ACC_TEST_IMAGE=$3

rpm -ivh ${DISTDIR}/imgbom_*_linux_amd64.rpm
imgbom version -v
imgbom ${ACC_TEST_IMAGE} -o json > ${RESULTSDIR}/acceptance-rpm-${ACC_TEST_IMAGE}.json 