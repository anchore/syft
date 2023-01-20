#!/usr/bin/env bash
set -eu

bold=$(tput bold)
normal=$(tput sgr0)

TEMP_DIR=.tmp
chronicle=$TEMP_DIR/chronicle

# we need all of the git state to determine the next version. Since tagging is done by
# the release pipeline it is possible to not have all of the tags from previous releases.
git fetch --tags

NEXT_VERSION=$($chronicle next-version)

echo "${bold}Proposed version:${normal} $NEXT_VERSION"
make changelog

while true; do
    read -p "${bold}Do you want to trigger a release with this version?${normal} [y/n] " yn
    case $yn in
        [Yy]* ) echo; break;;
        [Nn]* ) echo; echo "Cancelling release..."; exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

echo "${bold}Kicking off release for ${NEXT_VERSION}${normal}..."
echo
gh workflow run release.yaml -f version=${NEXT_VERSION}

echo
echo "${bold}Waiting for release to start...${normal}"
sleep 10

set +e

echo "${bold}Head to the release workflow to monitor the release:${normal} $(gh run list --workflow=release.yaml --limit=1 --json url --jq '.[].url')"
id=$(gh run list --workflow=release.yaml --limit=1 --json databaseId --jq '.[].databaseId')
gh run watch $id --exit-status || (echo ; echo "${bold}Logs of failed step:${normal}" && GH_PAGER="" gh run view $id --log-failed)
