#!/usr/bin/env bash
set -u

if ! git diff-index --quiet HEAD --; then
  git diff-index HEAD --
  git --no-pager diff
  echo "there are uncommitted changes, please commit them before running this check"
  exit 1
fi

success=true

if ! make generate-json-schema; then
  echo "Generating json schema failed"
  success=false
fi

if ! git diff-index --quiet HEAD --; then
  git diff-index HEAD --
  git --no-pager diff
  echo "JSON schema drift detected!"
  success=false
fi

if ! $success; then
  exit 1
fi
