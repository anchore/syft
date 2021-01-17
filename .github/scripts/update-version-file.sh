#!/usr/bin/env bash
set -ue

BIN="syft"
DISTDIR=$1
VERSION_TAG=$2

# the source of truth as to whether we want to notify users of an update is if the release just created is NOT
# flagged as a pre-release on github
if [[ "$(curl -SsL https://api.github.com/repos/anchore/${BIN}/releases/tags/${VERSION_TAG} | jq .prerelease)" == "true" ]] ; then
   echo "skipping publishing a version file (this is a pre-release: ${VERSION_TAG})"
   exit 0
fi

echo "creating and publishing version file"

# create a version file for version-update checks
VERSION_FILE="${DISTDIR}/VERSION"
echo "${VERSION_TAG}" | tee "${VERSION_FILE}"

# upload the version file that supports the application version update check
export AWS_DEFAULT_REGION=us-west-2
aws s3 cp "${VERSION_FILE}" s3://toolbox-data.anchore.io/${BIN}/releases/latest/VERSION
