#!/usr/bin/env bash
set -eux

DISTDIR=$1
ACC_DIR=$2
TEST_IMAGE=$3

TEST_IMAGE_TAR=/tmp/image.tar
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

# install skopeo (pinned to 1.1.0)
skopeo --version || brew install https://raw.githubusercontent.com/Homebrew/homebrew-core/75e8d7a40af77b48cc91f4bdb7d669f891a6de60/Formula/skopeo.rb

# fetch test image
skopeo --override-os linux copy docker://docker.io/${TEST_IMAGE} docker-archive:${TEST_IMAGE_TAR}
ls -alh ${TEST_IMAGE_TAR}

# run imgbom
chmod 755 ${DISTDIR}/imgbom_darwin_amd64/imgbom
${DISTDIR}/imgbom_darwin_amd64/imgbom version -v
${DISTDIR}/imgbom_darwin_amd64/imgbom docker-archive://${TEST_IMAGE_TAR} -vv -o json > ${REPORT}
cat ${REPORT}

# compare the results to a known good output
${ACC_DIR}/compare.py \
    ${GOLDEN_REPORT} \
    ${REPORT}
