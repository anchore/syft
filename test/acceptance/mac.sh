#!/usr/bin/env bash
set -eux

DISTDIR=$1
ACC_DIR=$2
TEST_IMAGE=$3

TEST_TYPE=mac
WORK_DIR=`mktemp -d -t "imgbom-acceptance-test-${TEST_TYPE}-XXXXXX"`
REPORT=${WORK_DIR}/acceptance-${TEST_TYPE}-${TEST_IMAGE}.json
GOLDEN_REPORT=${ACC_DIR}/test-fixtures/acceptance-${TEST_IMAGE}.json

# check if tmp dir was created
if [[ ! "${WORK_DIR}" || ! -d "${WORK_DIR}" ]]; then
  echo "Could not create temp dir"
  exit 1
fi

function cleanup {
  rm -rf "${WORK_DIR}"
}

trap cleanup EXIT

# install dependencies
jq --version || brew install jq
skopeo --version || brew install skopeo

# fetch test image
skopeo --override-os linux copy docker://docker.io/${TEST_IMAGE} dir:/tmp/test-img

# run imgbom
chmod 755 ${DISTDIR}/imgbom_darwin_amd64/imgbom
${DISTDIR}/imgbom_darwin_amd64/imgbom version -v
${DISTDIR}/imgbom_darwin_amd64/imgbom dir:///tmp/test-img -o json | tee ${REPORT}

# compare the results to a known good output
${ACC_DIR}/compare.sh \
    ${REPORT} \
    ${GOLDEN_REPORT}
