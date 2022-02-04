#!/usr/bin/env bash
set -eu

ARCHIVE_PATH="$1"
IS_SNAPSHOT="$2"

## grab utilities
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
. "$SCRIPT_DIR"/utils.sh

main() {
  perform_notarization=false
  archive_abs_path=$(realpath "$ARCHIVE_PATH")

  if [ ! -f "$archive_abs_path" ]; then
      echo "archive does not exist: $archive_abs_path"
  fi

  case "$IS_SNAPSHOT" in

    "1" |  "true" | "yes")
      commentary "assuming development setup..."
      . "$SCRIPT_DIR"/prep-signing-dev.sh
      ;;

    "0" |  "false" | "no")
      commentary "assuming production setup..."
      . "$SCRIPT_DIR"/prep-signing-prod.sh
      . "$SCRIPT_DIR"/notarize.sh
      perform_notarization=true
      ;;

    *)
      exit_with_error "could not determine if this was a production build (isSnapshot='$IS_SNAPSHOT')"
      ;;
  esac

  . "$SCRIPT_DIR"/sign.sh

  # load up all signing material into a keychain (note: this should set the MAC_SIGNING_IDENTITY env var)
  setup_signing

  # sign all of the binaries in the archive and recreate the input archive with the signed binaries
  sign_archive "$archive_abs_path" "$MAC_SIGNING_IDENTITY"

  # send all of the binaries off to apple to bless
  if $perform_notarization ; then
    notarize "$archive_abs_path"
  else
    commentary "skipping notarization..."
  fi
}

set +u
if [ -z "$SCRIPT" ]
then
    set -u
    # log all output
    mkdir -p "$SCRIPT_DIR/log"
    /usr/bin/script "$SCRIPT_DIR/log/signing-$(basename $ARCHIVE_PATH).txt" /bin/bash -c "$0 $*"
    exit $?
else
  set -u
  main
fi
