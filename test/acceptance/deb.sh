#!/usr/bin/env bash
set -eux

DISTDIR=$1
ACC_DIR=$2
TEST_IMAGE=$3
RESULTSDIR=$4

TEST_TYPE=deb
WORK_DIR=`mktemp -d -t "syft-acceptance-test-${TEST_TYPE}-XXXXXX"`
NORMAL_TEST_IMAGE=$(echo ${TEST_IMAGE} | tr ':' '-' )
REPORT=${WORK_DIR}/acceptance-${TEST_TYPE}-${NORMAL_TEST_IMAGE}.json
GOLDEN_REPORT=${ACC_DIR}/test-fixtures/acceptance-${NORMAL_TEST_IMAGE}.json

# check if tmp dir was created
if [[ ! "${WORK_DIR}" || ! -d "${WORK_DIR}" ]]; then
  echo "Could not create temp dir"
  exit 1
fi

function cleanup {
  rm -rf "${WORK_DIR}"
}

trap cleanup EXIT

# fetch test image
docker pull ${TEST_IMAGE}

# install and run syft
docker run --rm \
    -v /var/run/docker.sock://var/run/docker.sock \
    -v /${PWD}:/src \
    -v ${WORK_DIR}:${WORK_DIR} \
    -w /src \
    ubuntu:latest \
        /bin/bash -x -c "\
            DEBIAN_FRONTEND=noninteractive apt install ${DISTDIR}/syft_*_linux_amd64.deb -y && \
            syft version -v && \
            syft ${TEST_IMAGE} -vv -o json > ${REPORT} && \
            cat ${REPORT} \
        "

# keep the generated report around
cp ${REPORT} ${RESULTSDIR}

# compare the results to a known good output
${ACC_DIR}/compare.py \
    ${GOLDEN_REPORT} \
    ${REPORT} | tee ${RESULTSDIR}/acceptance-${TEST_TYPE}.txt
