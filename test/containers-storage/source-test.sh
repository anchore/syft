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
cleanup() {
  if [[ "$(id -u)" -eq 0 ]]; then
    rm -rf "$test_dir"
  else
    "$builder" unshare rm -rf "$test_dir"
  fi
}
trap cleanup EXIT

export CONTAINERS_STORAGE_CONF="$test_dir/storage.conf"
cat > "$CONTAINERS_STORAGE_CONF" <<EOF
[storage]
driver = "vfs"
graphroot = "$test_dir/graphroot"
rootless_storage_path = "$test_dir/graphroot"
runroot = "$test_dir/runroot"
EOF

build_context="$test_dir/context"
mkdir -p "$build_context"
cat > "$build_context/package.json" <<'EOF'
{"name":"syft-containers-storage-fixture","version":"1.2.3"}
EOF
cat > "$build_context/Containerfile" <<'EOF'
FROM scratch
COPY package.json /app/node_modules/syft-containers-storage-fixture/package.json
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

for scan_mode in explicit automatic; do
  source_args=()
  if [[ "$scan_mode" == explicit ]]; then
    source_args=(--from containers-storage)
  fi
  printf 'Testing %s image resolution with %s\n' "$scan_mode" "$builder"
  "$syft_binary" "${source_args[@]}" "$image_ref" --output json > "$test_dir/$scan_mode.json"
  jq -e --arg image_ref "$image_ref" '
    .source.type == "image" and
    .source.metadata.userInput == $image_ref and
    any(.artifacts[]; .name == "syft-containers-storage-fixture" and .version == "1.2.3" and .type == "npm")
  ' "$test_dir/$scan_mode.json" >/dev/null
done

printf 'Testing missing image with %s\n' "$builder"
if "$syft_binary" --from containers-storage localhost/syft-containers-storage-missing:latest --output json > "$test_dir/missing.json" 2> "$test_dir/missing.stderr"; then
  printf 'Expected the missing containers-storage image scan to fail\n' >&2
  exit 1
fi
grep -q 'containers-storage:' "$test_dir/missing.stderr"
if grep -q 'oci-registry:' "$test_dir/missing.stderr"; then
  printf 'Explicit containers-storage selection unexpectedly attempted registry resolution\n' >&2
  exit 1
fi