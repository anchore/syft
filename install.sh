#!/bin/sh
set -eu

PROJECT_NAME="syft"
OWNER=anchore
REPO="syft"
BINARY=syft
FORMAT=tar.gz
GITHUB_DOWNLOAD=https://github.com/${OWNER}/${REPO}/releases/download

#
# usage [script-name]
#
usage() (
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
)


# ------------------------------------------------------------------------
# https://github.com/client9/shlib - portable posix shell functions
# Public domain - http://unlicense.org
# https://github.com/client9/shlib/blob/master/LICENSE.md
# but credit (and pull requests) appreciated.
# ------------------------------------------------------------------------

is_command() (
  command -v "$1" >/dev/null
)

echo_stderr() (
  echo "$@" 1>&2
)

_logp=2
log_set_priority() {
  _logp="$1"
}

log_priority() (
  if test -z "$1"; then
    echo "$_logp"
    return
  fi
  [ "$1" -le "$_logp" ]
)

log_tag() (
  case $1 in
    0) echo "error" ;;
    1) echo "warn" ;;
    2) echo "info" ;;
    3) echo "debug" ;;
    4) echo "trace" ;;
    *) echo "$1" ;;
  esac
)

log_trace() (
  log_priority 4 || return 0
  echo_stderr "$(log_tag 4)" "$@"
)

log_debug() (
  log_priority 3 || return 0
  echo_stderr "$(log_tag 3)" "$@"
)

log_info() (
  log_priority 2 || return 0
  echo_stderr "$(log_tag 2)" "$@"
)

log_warn() (
  log_priority 1 || return 0
  echo_stderr "$(log_tag 1)" "$@"
)

log_err() (
  log_priority 0 || return 0
  echo_stderr "$(log_tag 0)" "$@"
)

uname_os_check() (
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
)

uname_arch_check() (
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
)

unpack() (
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
)

extract_from_dmg() (
  dmg_file=$1
  mount_point="/Volumes/tmp-dmg"
  hdiutil attach -quiet -nobrowse -mountpoint "${mount_point}" "${dmg_file}"
  cp -fR "${mount_point}/." ./
  hdiutil detach -quiet -force "${mount_point}"
)

http_download_curl() (
  local_file=$1
  source_url=$2
  set +u
  header=$3
  if [ -z "$header" ]; then
    code=$(curl -w '%{http_code}' -sL -o "$local_file" "$source_url")
  else
    code=$(curl -w '%{http_code}' -sL -H "$header" -o "$local_file" "$source_url")
  fi
  set -u
  if [ "$code" != "200" ]; then
    log_debug "http_download_curl received HTTP status $code"
    return 1
  fi
  return 0
)

http_download_wget() (
  local_file=$1
  source_url=$2
  header=$3
  if [ -z "$header" ]; then
    wget -q -O "$local_file" "$source_url"
  else
    wget -q --header "$header" -O "$local_file" "$source_url"
  fi
)

http_download() (
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
)

http_copy() (
  tmp=$(mktemp)
  http_download "${tmp}" "$1" "$2" || return 1
  body=$(cat "$tmp")
  rm -f "${tmp}"
  echo "$body"
)

hash_sha256() (
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
)

hash_sha256_verify() (
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
)

# ------------------------------------------------------------------------
# End of functions from https://github.com/client9/shlib
# ------------------------------------------------------------------------

asset_file_exists() (
  path="$1"
  if [ ! -f "${path}" ]; then
      return 1
  fi
)


#
# github_release_json [owner] [repo] [version]
#
# outputs release json string
#
github_release_json() (
  owner=$1
  repo=$2
  version=$3
  test -z "$version" && version="latest"
  giturl="https://github.com/${owner}/${repo}/releases/${version}"
  json=$(http_copy "$giturl" "Accept:application/json")
  test -z "$json" && return 1
  echo "${json}"
)

#
# extract_value [key-value-pair]
#
# outputs value from a colon delimited key-value pair
#
extract_value() (
  key_value="$1"
  IFS=':' read -r _ value << EOF
${key_value}
EOF
  echo "$value"
)

#
# extract_json_value [json] [key]
#
# outputs value of the key from the given json string
#
extract_json_value() (
  json="$1"
  key="$2"
  key_value=$(echo "${json}" | grep  -o "\"$key\":[^,]*[,}]" | tr -d '",}')

  extract_value "$key_value"
)

#
# github_release_tag [release-json]
#
# outputs release tag string
#
github_release_tag() (
  json="$1"
  tag=$(extract_json_value "${json}" "tag_name")
  test -z "$tag" && return 1
  echo "$tag"
)

#
# download_github_release_checksums [release-url-prefix] [name] [version] [output-dir]
#
# outputs path to the downloaded checksums file
#
download_github_release_checksums() (
  download_url="$1"
  name="$2"
  version="$3"
  output_dir="$4"

  checksum_filename=${name}_${version}_checksums.txt
  checksum_url=${download_url}/${checksum_filename}
  output_path="${output_dir}/${checksum_filename}"

  http_download "${output_path}" "${checksum_url}"
  asset_file_exists "${output_path}"

  echo "${output_path}"
)

#
# search_for_asset [checksums-file-path] [name] [os] [arch] [format]
#
# outputs name of the asset to download
#
search_for_asset() (
  checksum_path="$1"
  name="$2"
  os="$3"
  arch="$4"
  format="$5"

  log_trace "search_for_asset(checksum-path=${checksum_path}, name=${name}, os=${os}, arch=${arch}, format=${format})"

  asset_glob="${name}_.*_${os}_${arch}.${format}"
  output_path=$(grep -o "${asset_glob}" "${checksum_path}")

  log_trace "search_for_asset() returned '${output_path}'"

  echo "${output_path}"
)


uname_os() (
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    cygwin_nt*) os="windows" ;;
    mingw*) os="windows" ;;
    msys_nt*) os="windows" ;;
  esac
  uname_os_check "$os"
  echo "$os"
)

uname_arch() (
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
)

#
# get_release_tag [owner] [repo] [tag]
#
# outputs tag string
#
get_release_tag() (
  owner="$1"
  repo="$2"
  tag="$3"

  log_trace "get_release_tag(owner=${owner}, repo=${repo}, tag=${tag})"

  real_tag=$(github_release "${owner}/${repo}" "${tag}") && true
  if test -z "${real_tag}"; then
    log_err "unable to find '${tag}' - use 'latest' or see https://github.com/${owner}/${repo}/releases for details"
    exit 1
  fi
  echo "${real_tag}"
)

#
# tag_to_version [tag]
#
# outputs version string
#
tag_to_version() (
  tag="$1"

  log_trace "tag_to_version(tag=${tag})"

  echo "${tag#v}"
)

#
# get_binary_name [os] [arch] [default-name]
#
# outputs a the binary string name
#
get_binary_name() (
  os="$1"
  arch="$2"
  binary="$3"

  log_trace "get_binary_name(os=${os}, arch=${arch}, binary=${binary})"

  case "${os}" in
    windows) binary="${binary}.exe" ;;
  esac
  echo "${binary}"
)


#
# get_format_name [os] [arch] [default-format]
#
get_format_name() (
  os="$1"
  arch="$2"
  format="$3"

  log_trace "get_format_name(os=${os}, arch=${arch}, format=${format})"

  case ${os} in
    darwin) format=dmg ;;
    windows) format=zip ;;
  esac
  case "${os}/${arch}" in
    darwin/arm64) format=zip ;;
  esac
  echo "${format}"
)


#
# download_release [release-url-prefix] [name] [os] [arch] [version] [format]
#
# output the filepath to the verified raw asset
#
download_asset() (
  download_url="$1"
  name="$2"
  os="$3"
  arch="$4"
  version="$5"
  format="$6"
  destination="$7"

  log_trace "download_asset(url=${download_url}, name=${name}, os=${os}, arch=${arch}, version=${version}, format=${format}, destination=${destination})"

  checksums_filepath=$(download_github_release_checksums "${download_url}" "${name}" "${version}" "${destination}")
  asset_filename=$(search_for_asset "${checksums_filepath}" "${name}" "${os}" "${arch}" "${format}")

  # don't continue if we couldn't find a matching asset from the checksums file
  if [ -z "${asset_filename}" ]; then
      return
  fi

  asset_url="${download_url}/${asset_filename}"
  asset_filepath="${destination}/${asset_filename}"
  http_download "${asset_filepath}" "${asset_url}"

  # macOS has its own secure verification mechanism, and checksums.txt is not used.
  if [ "$os" != "darwin" ]; then
    hash_sha256_verify "${asset_filepath}" "${checksums_filepath}"
  fi

  log_trace "download_asset() returned '${asset_filepath}'"

  echo "${asset_filepath}"
)

#
# install_asset [asset-path] [destination-path] [binary]
#
install_asset() (
  asset_filepath="$1"
  destination="$2"
  binary="$3"

  # don't continue if we don't have anything to install
  if [ -z "${asset_filepath}" ]; then
      return
  fi

  archive_dir=$(dirname "${asset_filepath}")

  # unarchive the downloaded archive to the temp dir
  (cd "${archive_dir}" && unpack "${asset_filepath}")

  # create the destination dir
  test ! -d "${destination}" && install -d "${destination}"

  # install the binary to the destination dir
  install "${archive_dir}/${binary}" "${destination}/"
)



main() (
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

  tmpdir=$(mktemp -d)
  trap 'rm -rf -- "$tmpdir"' EXIT

  # run the application

  os=$(uname_os)
  arch=$(uname_arch)
  binary=$(get_binary_name "${os}" "${arch}" "${BINARY}")
  tag=$(get_release_tag "${OWNER}" "${REPO}" "${tag}")
  version=$(tag_to_version "${tag}")
  format=$(get_format_name "${os}" "${arch}" "${FORMAT}")

  log_info "found version: ${version} for ${tag}/${os}/${arch}"
  log_debug "downloading files into ${tmpdir}"

  asset_filepath=$(download_asset "${GITHUB_DOWNLOAD}" "${PROJECT_NAME}" "${os}" "${arch}" "${version}" "${tmpdir}")
  install_asset "${asset_filepath}" "${bin_dir}" "${binary}"

  log_info "installed ${bin_dir}/${binary}"
)