#!/usr/bin/env bash
set -eu

IS_SNAPSHOT="$1"

## grab utilities
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
. "$SCRIPT_DIR"/utils.sh

main() {

  case "$IS_SNAPSHOT" in

    "1" |  "true" | "yes")
      commentary "assuming development setup..."
      . "$SCRIPT_DIR"/setup-dev.sh
      ;;

    "0" |  "false" | "no")
      commentary "assuming production setup..."
      . "$SCRIPT_DIR"/setup-prod.sh
      ;;

    *)
      exit_with_error "could not determine if this was a production build (isSnapshot='$IS_SNAPSHOT')"
      ;;
  esac

  # load up all signing material into a keychain (note: this should set the MAC_SIGNING_IDENTITY env var)
  setup_signing

  # write out identity to a file
  echo -n "$MAC_SIGNING_IDENTITY" > "$SCRIPT_DIR/$SIGNING_IDENTITY_FILENAME"
}

set +u
if [ -z "$SCRIPT" ]
then
    set -u
    # log all output
    mkdir -p "$SCRIPT_DIR/log"
    /usr/bin/script "$SCRIPT_DIR/log/setup.txt" /bin/bash -c "$0 $*"
    exit $?
elif [ -n "$SKIP_SIGNING" ]; then
    commentary "skipping signing setup..."
else
  set -u
  main
fi
