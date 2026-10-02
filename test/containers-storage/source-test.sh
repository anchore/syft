#!/usr/bin/env bash
set -euo pipefail

builder="${1:?expected podman or buildah}"
case "$builder" in
  podman|buildah) ;;
  *)
    printf 'unsupported image builder: %s\n' "$builder" >&2
    exit 2
    ;;
esac

workspace_root="$(cd "$(dirname "$0")/../.." && pwd)"
syft_binary="${SYFT_BINARY_LOCATION:-}"
if [[ -z "$syft_binary" ]]; then
  syft_binary="$(find "$workspace_root/snapshot" -type f -path '*/linux-build_linux_amd64*/syft' -print -quit)"
fi
if [[ -z "$syft_binary" ]]; then
  printf 'Linux snapshot binary not found under %s/snapshot\n' "$workspace_root" >&2
  exit 1
fi
chmod +x "$syft_binary"

test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

export CONTAINERS_STORAGE_CONF="$test_dir/storage.conf"
cat > "$CONTAINERS_STORAGE_CONF" <<EOF
[storage]
driver = "vfs"
graphroot = "$test_dir/graphroot"
runroot = "$test_dir/runroot"
EOF

build_context="$test_dir/context"
mkdir -p "$build_context"
printf 'containers-storage test payload\n' > "$build_context/payload.txt"
cat > "$build_context/Containerfile" <<'EOF'
FROM scratch
COPY payload.txt /payload.txt
EOF

image_ref="localhost/syft-containers-storage-test:latest"
case "$builder" in
  podman)
    podman build --pull=never --tag "$image_ref" "$build_context"
    ;;
  buildah)
    buildah bud --pull=false --tag "$image_ref" "$build_context"
    ;;
esac

"$syft_binary" --from containers-storage "$image_ref" --output json > "$test_dir/sbom.json"
jq -e --arg image_ref "$image_ref" '.source.type == "image" and .source.metadata.userInput == $image_ref' "$test_dir/sbom.json" >/dev/null