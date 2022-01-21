#!/bin/sh
set -e

PROJECT_NAME="syft"
OWNER=anchore
REPO="syft"
BINARY=syft
FORMAT=tar.gz
GITHUB_DOWNLOAD=https://github.com/${OWNER}/${REPO}/releases/download

#
# usage [script-name]
#
usage() {
  this=$1
  cat <<EOF
$this: download go binaries for anchore/syft

Usage: $this [-b] bindir [-d] [tag]
  -b sets bindir or installation directory, Defaults to ./bin
  -d turns on debug logging
   [tag] is a tag from

   https://github.com/anchore/syft/releases
   If tag is missing, then the latest will be used.
EOF
  exit 2
}


# ------------------------------------------------------------------------
# https://github.com/client9/shlib - portable posix shell functions
# Public domain - http://unlicense.org
# https://github.com/client9/shlib/blob/master/LICENSE.md
# but credit (and pull requests) appreciated.
# ------------------------------------------------------------------------

is_command() {
  command -v "$1" >/dev/null
}

echo_stderr() {
  echo "$@" 1>&2
}

_logp=3
log_set_priority() {
  _logp="$1"
}

log_priority() {
  if test -z "$1"; then
    echo "$_logp"
    return
  fi
  [ "$1" -le "$_logp" ]
}

log_tag() {
  case $1 in
    0) echo "error" ;;
    1) echo "warn" ;;
    2) echo "info" ;;
    3) echo "debug" ;;
    *) echo "$1" ;;
  esac
}

log_debug() {
  log_priority 3 || return 0
  echo_stderr "$(log_tag 3)" "$@"
}

log_info() {
  log_priority 2 || return 0
  echo_stderr "$(log_tag 2)" "$@"
}

log_warn() {
  log_priority 1 || return 0
  echo_stderr "$(log_tag 1)" "$@"
}

log_err() {
  log_priority 0 || return 0
  echo_stderr "$(log_tag 0)" "$@"
}

uname_os_check() {
  os=$(uname_os)
  case "$os" in
    darwin) return 0 ;;
    dragonfly) return 0 ;;
    freebsd) return 0 ;;
    linux) return 0 ;;
    android) return 0 ;;
    nacl) return 0 ;;
    netbsd) return 0 ;;
    openbsd) return 0 ;;
    plan9) return 0 ;;
    solaris) return 0 ;;
    windows) return 0 ;;
  esac
  log_err "uname_os_check '$(uname -s)' got converted to '$os' which is not a GOOS value. Please file bug at https://github.com/client9/shlib"
  return 1
}

uname_arch_check() {
  arch=$(uname_arch)
  case "$arch" in
    386) return 0 ;;
    amd64) return 0 ;;
    arm64) return 0 ;;
    armv5) return 0 ;;
    armv6) return 0 ;;
    armv7) return 0 ;;
    ppc64) return 0 ;;
    ppc64le) return 0 ;;
    mips) return 0 ;;
    mipsle) return 0 ;;
    mips64) return 0 ;;
    mips64le) return 0 ;;
    s390x) return 0 ;;
    amd64p32) return 0 ;;
  esac
  log_err "uname_arch_check '$(uname -m)' got converted to '$arch' which is not a GOARCH value.  Please file bug report at https://github.com/client9/shlib"
  return 1
}

unpack() {
  archive=$1
  case "${archive}" in
    *.tar.gz | *.tgz) tar --no-same-owner -xzf "${archive}" ;;
    *.tar) tar --no-same-owner -xf "${archive}" ;;
    *.zip) unzip "${archive}" ;;
    *.dmg) extract_from_dmg "${archive}" ;;
    *)
      log_warn "unpack unknown archive format for ${archive}"
      return 1
      ;;
  esac
}

extract_from_dmg() {
  dmg_file=$1
  mount_point="/Volumes/tmp-dmg"
  hdiutil attach -quiet -nobrowse -mountpoint "${mount_point}" "${dmg_file}"
  cp -fR "${mount_point}/." ./
  hdiutil detach -quiet -force "${mount_point}"
}

http_download_curl() {
  local_file=$1
  source_url=$2
  header=$3
  if [ -z "$header" ]; then
    code=$(curl -w '%{http_code}' -sL -o "$local_file" "$source_url")
  else
    code=$(curl -w '%{http_code}' -sL -H "$header" -o "$local_file" "$source_url")
  fi
  if [ "$code" != "200" ]; then
    log_debug "http_download_curl received HTTP status $code"
    return 1
  fi
  return 0
}

http_download_wget() {
  local_file=$1
  source_url=$2
  header=$3
  if [ -z "$header" ]; then
    wget -q -O "$local_file" "$source_url"
  else
    wget -q --header "$header" -O "$local_file" "$source_url"
  fi
}

http_download() {
  log_debug "http_download $2"
  if is_command curl; then
    http_download_curl "$@"
    return
  elif is_command wget; then
    http_download_wget "$@"
    return
  fi
  log_err "http_download unable to find wget or curl"
  return 1
}

http_copy() {
  tmp=$(mktemp)
  http_download "${tmp}" "$1" "$2" || return 1
  body=$(cat "$tmp")
  rm -f "${tmp}"
  echo "$body"
}

hash_sha256() {
  TARGET=${1:-/dev/stdin}
  if is_command gsha256sum; then
    hash=$(gsha256sum "$TARGET") || return 1
    echo "$hash" | cut -d ' ' -f 1
  elif is_command sha256sum; then
    hash=$(sha256sum "$TARGET") || return 1
    echo "$hash" | cut -d ' ' -f 1
  elif is_command shasum; then
    hash=$(shasum -a 256 "$TARGET" 2>/dev/null) || return 1
    echo "$hash" | cut -d ' ' -f 1
  elif is_command openssl; then
    hash=$(openssl -dst openssl dgst -sha256 "$TARGET") || return 1
    echo "$hash" | cut -d ' ' -f a
  else
    log_err "hash_sha256 unable to find command to compute sha-256 hash"
    return 1
  fi
}

hash_sha256_verify() {
  TARGET=$1
  checksums=$2
  if [ -z "$checksums" ]; then
    log_warn "hash_sha256_verify checksum file not specified in arg2"
    return 1
  fi
  BASENAME=${TARGET##*/}
  want=$(grep "${BASENAME}" "${checksums}" 2>/dev/null | tr '\t' ' ' | cut -d ' ' -f 1)
  if [ -z "$want" ]; then
    log_warn "hash_sha256_verify unable to find checksum for '${TARGET}' in '${checksums}'"
    return 1
  fi
  got=$(hash_sha256 "$TARGET")
  if [ "$want" != "$got" ]; then
    log_warn "hash_sha256_verify checksum for '$TARGET' did not verify ${want} vs $got"
    return 1
  fi
}

# ------------------------------------------------------------------------
# End of functions from https://github.com/client9/shlib
# ------------------------------------------------------------------------

#
# github_release_json [owner] [repo] [version]
#
# outputs release json string
#
github_release_json() {
  owner=$1
  repo=$2
  version=$3
  test -z "$version" && version="latest"
  giturl="https://github.com/${owner}/${repo}/releases/${version}"
  json=$(http_copy "$giturl" "Accept:application/json")
  test -z "$json" && return 1
  echo "${json}"
}

extract_value() {
  key_value="$1"
  IFS=':' read -r _ value << EOF
${key_value}
EOF
  echo "$value"
}

extract_json_value() {
  json="$1"
  key="$2"
  key_value=$(echo "${json}" | grep  -o "\"$key\":[^,]*[,}]" | tr -d '",}')

  extract_value "$key_value"
}

extract_json_values() {
  json="$1"
  key="$2"
  key_values=$(echo "${json}" | grep  -o "\"$key\":[^,]*[,}]" | tr -d '",}' | sed "s/${key}://g")

  # avoid globbing (expansion of *)
  set -f
  array=(${key_values})
  for i in "${!array[@]}"
  do
      echo "${array[i]}\n"
  done
  set +f
}

#
# github_release_asset_download_url [github-assets-json] [os] [arch] [format]
#
github_release_asset_download_url() {
  json="$1"
  os="$2"
  arch="$3"
  format="$4"

  suffix="_${os}_${arch}.${format}"
  key=browser_download_url

  key_values=$(echo "${json}" | grep  -o "\"$key\":[^,]*[,}]" | tr -d '",}' | sed "s/${key}://g")

  # avoid globbing (expansion of *)
  set -f
  array=(${key_values})
  for i in "${!array[@]}"
  do
      url="${array[i]}"
      case $i in *.c)
        echo $url
        return 0
        ;;
      esac
  done
  set +f
  return 1
}

#
# github_release_id [release-json]
#
# outputs release id string
#
github_release_id() {
  json="$1"
  id=$(extract_json_value "${json}" "id")
  test -z "$id" && return 1
  echo "$id"
}

#
# github_release_tag [release-json]
#
# outputs release tag string
#
github_release_tag() {
  json="$1"
  tag=$(extract_json_value "${json}" "tag_name")
  test -z "tag" && return 1
  echo "tag"
}

#
# github_release_assets_json [owner] [repo]  [release-id]
#
# outputs release version string
#
github_release_assets_json() {
  owner="${1:?Owner name required.}"
  repo="${2:?Repo name required.}"
  release_id="${3:?Release ID required.}"

  giturl="https://api.github.com/repos/${owner}/${repo}/releases/${release_id}/assets"
  json=$(http_copy "$giturl" "Accept:application/vnd.github.v3+json")
  test -z "$json" && return 1
  echo "${json}"
}


#json="$(github_release_json "anchore" "syft" "v0.36.0")"
#release_id=$(github_release_id "${json}")
#echo $release_id
#assets_json="$(github_release_assets_json "anchore" "syft" $release_id)"

echo $(extract_json_values "${y}" "browser_download_url")


uname_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    cygwin_nt*) os="windows" ;;
    mingw*) os="windows" ;;
    msys_nt*) os="windows" ;;
  esac
  uname_os_check "$os"
  echo "$os"
}

uname_arch() {
  arch=$(uname -m)
  case $arch in
    x86_64) arch="amd64" ;;
    x86) arch="386" ;;
    i686) arch="386" ;;
    i386) arch="386" ;;
    aarch64) arch="arm64" ;;
    armv5*) arch="armv5" ;;
    armv6*) arch="armv6" ;;
    armv7*) arch="armv7" ;;
  esac
  uname_arch_check "${arch}"
  echo "${arch}"
}

#
# get_release_tag [owner] [repo] [tag]
#
# outputs tag string
#
get_release_tag() {
  owner="$1"
  repo="$2"
  tag="$3"
  real_tag=$(github_release "${owner}/${repo}" "${tag}") && true
  if test -z "${real_tag}"; then
    log_err "unable to find '${tag}' - use 'latest' or see https://github.com/${owner}/${repo}/releases for details"
    exit 1
  fi
  echo "${real_tag}"
}

#
# tag_to_version [tag]
#
# outputs version string
#
tag_to_version() {
  tag="$1"
  version=${TAG#v}
}

#
# adjust_binary [os] [arch] [default-name]
#
# outputs a the binary string name
#
adjust_binary() {
  os="$1"
  arch="$2"
  binary="$3"

  case "${os}" in
    windows) binary="${binary}.exe" ;;
  esac
  echo "${binary}"
}


#
# adjust_format [os] [arch] [default-format]
#
adjust_format() {
  os="$1"
  arch="$2"
  format="$3"

  case ${os} in
    darwin) format=dmg ;;
    windows) format=zip ;;
  esac
  case "${os}/${arch}" in
    darwin/arm64) format=zip ;;
  esac
  echo "${format}"
}


#
# execute [os] [arch] [version]
#
execute() {
  os="$1"
  arch="$2"
  version="$3"

  name=${PROJECT_NAME}_${version}_${os}_${arch}
  archive=${name}.${FORMAT}
  archive_url=${GITHUB_DOWNLOAD}/${TAG}/${archive}
  checksum=${PROJECT_NAME}_${version}_checksums.txt
  checksum_url=${GITHUB_DOWNLOAD}/${TAG}/${checksum}

  tmpdir=$(mktemp -d)
  trap 'rm -rf -- "$tmpdir"' EXIT

  log_debug "downloading files into ${tmpdir}"
  http_download "${tmpdir}/${archive}" "${archive_url}"
  http_download "${tmpdir}/${checksum}" "${checksum_url}"

  # macOS has its own secure verification mechanism, and checksums.txt is not used.
  if [ "$OS" != "darwin" ]; then
    hash_sha256_verify "${tmpdir}/${archive}" "${tmpdir}/${checksum}"
  fi

  # unarchive the downloaded archive to the temp dir
  (cd "${tmpdir}" && unpack "${archive}")

  # create the destination dir
  test ! -d "${bin_dir}" && install -d "${bin_dir}"

  # install the binary to the destination dir
  install "${tmpdir}/${binary}" "${bin_dir}/"
}



main() {
  # parse arguments

  bin_dir=${bin_dir:-./bin}
  while getopts "b:dh?x" arg; do
    case "$arg" in
      b) bin_dir="$OPTARG" ;;
      d) log_set_priority 10 ;;
      h | \?) usage "$0" ;;
      x) set -x ;;
    esac
  done
  shift $((OPTIND - 1))
  tag=$1

  if [ -z "${tag}" ]; then
    log_info "checking GitHub for latest tag"
  else
    log_info "checking GitHub for tag '${tag}'"
  fi

  os=$(uname_os)
  arch=$(uname_arch)
  binary=$(adjust_binary "${os}" "${arch}" "${BINARY}")
  tag=$(get_release_tag "${owner}" "${repo}" "${tag}")
  version=$(tag_to_version "${tag}")
  format=$(adjust_format "${os}" "${arch}" "${FORMAT}")

  log_info "found version: ${version} for ${tag}/${os}/${arch}"

  execute "${os}" "${arch}" "${version}"

  log_info "installed ${bin_dir}/${binary}"
}