#!/usr/bin/env bash
set -u

if [ "$(git status --porcelain | wc -l)" -ne "0" ]; then
  echo "  🔴 there are uncommitted changes, please commit them before running this check"
  exit 1
fi

if ! make generate-capabilities REFRESH=false; then
  echo "Generating capability descriptions failed"
  exit 1
fi

if [ "$(git status --porcelain | wc -l)" -ne "0" ]; then
  echo "  🔴 there is drift in capability descriptions! Please run 'make generate-capabilities' and commit the changes."
  exit 1
fi