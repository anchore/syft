#!/usr/bin/env bash
set -eu -o pipefail

BIN="syft"
TEMPDIR=$(mktemp -d syft-homebrew-formula-generate-XXXXXX)
VERSION_TAG=$1
HOMEBREW_FORMULA_FILE=$2

trap "rm -f ${TEMPDIR}/*; rmdir ${TEMPDIR};" EXIT

# dependencies: curl, jq, openssl

RELEASE_URL="https://api.github.com/repos/anchore/${BIN}/releases/tags/${VERSION_TAG}"
echo "Using release: ${RELEASE_URL}"
curl -sSL "${RELEASE_URL}" > "${TEMPDIR}/release.json"

function asset_url() { 
  cat "${1}" | jq -r ".assets[] | select(.name | contains(\"${2}\")) | .browser_download_url"
}

function sha256() {
  openssl dgst -sha256 "${1}" | cut -d " " -f 2
}

export DARWIN_AMD64_ASSET_URL=$(asset_url "${TEMPDIR}/release.json" "darwin_amd64.zip")
curl -sSL "${DARWIN_AMD64_ASSET_URL}" > "${TEMPDIR}/darwin_amd64_asset"
export DARWIN_AMD64_ASSET_SHA256=$(sha256 "${TEMPDIR}/darwin_amd64_asset")

export LINUX_AMD64_ASSET_URL=$(asset_url "${TEMPDIR}/release.json" "linux_amd64.tar.gz")
curl -sSL "${LINUX_AMD64_ASSET_URL}" > "${TEMPDIR}/linux_amd64_asset"
export LINUX_AMD64_ASSET_SHA256=$(sha256 "${TEMPDIR}/linux_amd64_asset")

export VERSION=${VERSION_TAG#v}

cat > ${HOMEBREW_FORMULA_FILE} <<-EOF
class Syft < Formula
  desc "A tool that generates a Software Bill Of Materials (SBOM) from container images and filesystems"
  homepage "https://github.com/anchore/syft"
  version "$VERSION"
  bottle :unneeded

  if OS.mac?
    if Hardware::CPU.intel?
      url "$DARWIN_AMD64_ASSET_URL"
      sha256 "$DARWIN_AMD64_ASSET_SHA256"
    end
  elsif OS.linux?
    if Hardware::CPU.intel?
      url "$LINUX_AMD64_ASSET_URL"
      sha256 "$LINUX_AMD64_ASSET_SHA256"
    end
  end

  def install
    bin.install "syft"
  end
end
EOF

echo "Generated ${HOMEBREW_FORMULA_FILE}:"
cat ${HOMEBREW_FORMULA_FILE}