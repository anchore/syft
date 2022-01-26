#!/usr/bin/env bash
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

ARCHIVE_PATH="$1"

if [ -z "$SCRIPT" ]
then
    # log all output
    mkdir -p "$SCRIPT_DIR/log"
    /usr/bin/script "$SCRIPT_DIR/log/signing-$(basename $ARCHIVE_PATH).txt" /bin/bash -c "$0 $*"
    exit $?
fi

set -u

IS_SNAPSHOT="$2"

## grab utilities
. "$SCRIPT_DIR"/utils.sh

ARCHIVE_ABS_PATH=$(realpath $ARCHIVE_PATH)

if [ ! -f "$ARCHIVE_ABS_PATH" ]; then
    echo "archive does not exist: $ARCHIVE_ABS_PATH"
fi

case "$IS_SNAPSHOT" in

  "1" |  "true" | "yes")
    title "setting up developer certificate material"
    . "$SCRIPT_DIR"/prep-dev.sh
    ;;

  "0" |  "false" | "no")
    title "setting up production certificate material"
    . "$SCRIPT_DIR"/prep-prod.sh
    ;;

  *)
    exit_with_error "could not determine if this was a production build (isSnapshot='$IS_SNAPSHOT')"
    ;;
esac

# load up all signing material into a keychain
setup_signing

if [ -z "$MAC_SIGNING_IDENTITY" ]; then
  echo "failed to find signing identity"
  exit 1
fi

UNARCHIVED_PATH=$(mktemp -d)
trap "rm -rf -- $UNARCHIVED_PATH" EXIT

sign() {
  EXE_PATH=$1

  if [ -x "$EXE_PATH" ] && file -b "$EXE_PATH" | grep -q "Mach-O"
  then
      echo "signing $EXE_PATH ..."
  else
      echo "skip signing $EXE_PATH ..."
      return 0
  fi

  set -x

  codesign \
    -s "$MAC_SIGNING_IDENTITY" \
    -f \
    --verbose=4 \
    --timestamp \
    --options runtime \
      $EXE_PATH

  codesign --verify $EXE_PATH  --verbose=4
}

export -f sign

title "getting contents from the release archive: $ARCHIVE_ABS_PATH"
tar -C "$UNARCHIVED_PATH" -xvf "$ARCHIVE_ABS_PATH"
rm "$ARCHIVE_ABS_PATH"

title "signing binaries found in the release archive"
find "$UNARCHIVED_PATH" -perm +111 -type f -exec bash -c 'sign "{}"' \;

title "recreating the release archive: $ARCHIVE_ABS_PATH"
(cd $UNARCHIVED_PATH && tar -czvf "$ARCHIVE_ABS_PATH" .)
