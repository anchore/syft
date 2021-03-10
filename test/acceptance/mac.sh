#!/usr/bin/env bash
set -eux
set -o pipefail

DISTDIR=$1
ACC_DIR=$2
TEST_IMAGE=$3
RESULTSDIR=$4

TEST_TYPE=mac
WORK_DIR=$(mktemp -d -t "syft-acceptance-test-${TEST_TYPE}-XXXXXX")
TEST_IMAGE_TAR=${WORK_DIR}/image.tar
NORMAL_TEST_IMAGE=$(echo "${TEST_IMAGE}" | tr ':' '-' )
REPORT=${WORK_DIR}/acceptance-${TEST_TYPE}-${NORMAL_TEST_IMAGE}.json
GOLDEN_REPORT=${ACC_DIR}/test-fixtures/acceptance-${NORMAL_TEST_IMAGE}.json

SYFT_PATH="${DISTDIR}/syft_darwin_amd64/syft"

# check if tmp dir was created
if [[ ! "${WORK_DIR}" || ! -d "${WORK_DIR}" ]]; then
  echo "Could not create temp dir"
  exit 1
fi

trap "rm -f ${WORK_DIR}/*; rmdir ${WORK_DIR};" EXIT

function cleanup {
  # we should still preserve previous failures
  exit_code=$?
  rm -rf "${WORK_DIR}"
  exit ${exit_code}
}

trap cleanup EXIT

# install skopeo
skopeo --version || brew install skopeo

# fetch test image
skopeo --override-os linux --insecure-policy copy "docker://docker.io/${TEST_IMAGE}" "docker-archive:${TEST_IMAGE_TAR}"
ls -alh "${TEST_IMAGE_TAR}"

# run syft
chmod 755 "${SYFT_PATH}"
"${SYFT_PATH}" version
SYFT_CHECK_FOR_APP_UPDATE=0 "${SYFT_PATH}" "docker-archive://${TEST_IMAGE_TAR}" -vv -o json > "${REPORT}"

# keep the generated report around
mkdir -p "${RESULTSDIR}"
cp "${REPORT}" "${RESULTSDIR}"

# compare the results to a known good output
${ACC_DIR}/compare.py \
    "${GOLDEN_REPORT}" \
    "${REPORT}" | tee "${RESULTSDIR}/acceptance-${TEST_TYPE}.txt"
