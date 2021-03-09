#!/usr/bin/env bash
set -eu

BIN="syft"
DISTDIR=$1
VERSION=$2
TEMPDIR=$3

SYFT_BIN_PATH=${DISTDIR}/${BIN}_linux_amd64/${BIN}

# stage the release tar directory
WORK_DIR=$(mktemp -d -t "syft-packaging-XXXXXX")
cp ./README.md ${WORK_DIR}
cp ./LICENSE ${WORK_DIR}
cp ${SYFT_BIN_PATH} ${WORK_DIR}

# produce .tar.gz
tar -cvzf "${DISTDIR}/${BIN}_${VERSION}_linux_amd64.tar.gz" -C ${WORK_DIR} .

# produce .deb, .rpm
NFPM_CONFIG=$(mktemp -t "syft-nfpm-cfg-XXXXXX")
cat > ${NFPM_CONFIG} <<-EOF
name: "syft"
license: "Apache 2.0"
maintainer: "Anchore, Inc"
homepage: "https://github.com/anchore/syft"
description: "A tool that generates a Software Bill Of Materials (SBOM) from container images and filesystems"
contents:
  - src: ${SYFT_BIN_PATH}
    dst: /usr/local/bin/syft
EOF

for packager in "deb" "rpm"; do
  ${TEMPDIR}/nfpm -f ${NFPM_CONFIG} pkg --packager="$packager" --target="${DISTDIR}/${BIN}_${VERSION}_linux_amd64.$packager"
done

# produce integrity-check files (checksums.txt, checksums.txt.sig)
pushd "${DISTDIR}"
  CHECKSUMS_FILE="${BIN}_${VERSION}_checksums.txt"
  echo "" > "$CHECKSUMS_FILE"
  for file in ./*linux*.*; do
    openssl dgst -sha256 "$file" >> "$CHECKSUMS_FILE"
  done
  gpg --detach-sign "$CHECKSUMS_FILE"
popd