#!/usr/bin/env bash
set -eu

BOLD="$(tput -T linux bold)"
RED="$(tput -T linux setaf 1)"
RESET="$(tput -T linux sgr0)"
FAIL="${BOLD}${RED}"
SUCCESS="${BOLD}"
JQ_ARGS="-S .artifacts"

if ! command -v jq &> /dev/null ;then
    JQ_IMAGE="imega/jq:latest"
    JQ_CMD="docker run --rm -i ${JQ_IMAGE} ${JQ_ARGS}"
    docker pull "${JQ_IMAGE}"
else
    JQ_CMD="jq ${JQ_ARGS}"
fi

if [[ $(cat $1 | ${JQ_CMD}) ]]; then
    set -x
    # compare the output of both results
    diff <(cat $1 | ${JQ_CMD}) <(cat $2 | ${JQ_CMD})
    set +x
    echo "${SUCCESS}Comparison passed!${RESET}"
else
    exit "${FAIL}Failing since one of the test files is empty ($1)${RESET}"
fi