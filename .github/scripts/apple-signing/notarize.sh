#!/usr/bin/env bash
set -ue

set +xu
if [ -z "$AC_USERNAME" ]; then
  exit_with_error "AC_USERNAME not set"
fi

if [ -z "$AC_PASSWORD" ]; then
  exit_with_error "AC_PASSWORD not set"
fi
set -u

# repackage [archive-path]
#
# returns an archive compatible for Apple's notarization process, repackaging the input archive as needed
#
repackage() {
  archive=$1

  case "$archive" in
    *.tar.gz)
      new_archive=${archive%.tar.gz}.zip
      (
        tmp_dir=$(mktemp -d)
        cd "$tmp_dir"
        # redirect stdout to stderr to preserve the return value
        tar xzf "$archive" && zip "$new_archive" ./* 1>&2
        rm -rf "$tmp_dir"
      )
      echo "$new_archive"
      ;;
    *.zip)
      echo "$archive"
      ;;
    *) return 1
      ;;
  esac
}

# notarize [archive-path]
#
notarize() {
  archive_path=$1

  title "notarizing binaries found in the release archive"

  payload_archive_path=$(repackage "$archive_path")
  if [ "$?" != "0" ]; then
    exit_with_error "cannot prepare payload for notarization: $archive_path"
  fi

  if [ ! -f "$payload_archive_path" ]; then
    exit_with_error "cannot find payload for notarization: $payload_archive_path"
  fi

  # install gon
  which gon || (brew tap mitchellh/gon && brew install mitchellh/gon/gon)

  # create config (note: json via stdin with gon is broken, can only use HCL from file)
  tmp_file=$(mktemp).hcl

  cat <<EOF > "$tmp_file"
notarize {
  path = "$payload_archive_path"
  bundle_id = "com.anchore.toolbox.syft"
}

apple_id {
   username = "$AC_USERNAME"
   password = "@env:AC_PASSWORD"
}
EOF

  gon -log-level info "$tmp_file"

  result="$?"

  rm "$tmp_file"

  if [ "$result" -ne "0" ]; then
      exit_with_error "notarization failed"
  fi
}

