#!/usr/bin/env bash
# build an image with podman or buildah into an isolated containers-storage store, then verify syft can scan it out
# of that store (for both the vfs and overlay drivers) and that plain image references never touch the store.
#
# usage: SYFT_BINARY_LOCATION=/path/to/syft source-test.sh podman|buildah
set -euo pipefail

builder="${1:?expected podman or buildah}"
case "$builder" in
  podman|buildah) ;;
  *)
    printf 'unsupported image builder: %s\n' "$builder" >&2
    exit 2
    ;;
esac

syft_binary="${SYFT_BINARY_LOCATION:?expected SYFT_BINARY_LOCATION to point at a linux syft binary built with containers-storage support}"
if [[ ! -f "$syft_binary" ]]; then
  printf 'syft binary not found at %s\n' "$syft_binary" >&2
  exit 1
fi
chmod +x "$syft_binary"

test_dir="$(mktemp -d)"
# the overlay driver bind-mounts its graphroot onto itself (in the builder's user namespace when rootless), which must
# be unmounted before the store can be removed. Cleanup is best-effort so it never masks the test result.
cleanup_store() {
  umount -l "$1"/*/graphroot/overlay 2>/dev/null || true
  rm -rf "$1"
}
cleanup() {
  if [[ "$(id -u)" -eq 0 ]]; then
    cleanup_store "$test_dir"
  else
    "$builder" unshare bash -c "$(declare -f cleanup_store); cleanup_store \"\$1\"" _ "$test_dir"
  fi || printf 'warning: unable to fully clean up %s\n' "$test_dir" >&2
}
trap cleanup EXIT

# a rootless store can only be opened from inside the builder's user namespace (as podman/buildah/skopeo do for
# themselves), so rootless users must run syft under "<builder> unshare". Root opens the store directly.
run_syft() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$syft_binary" "$@"
  else
    "$builder" unshare "$syft_binary" "$@"
  fi
}

build_context="$test_dir/context"
mkdir -p "$build_context"
cat > "$build_context/package.json" <<'EOF'
{"name":"syft-cs-fixture","version":"1.2.3"}
EOF
cat > "$build_context/Containerfile" <<'EOF'
FROM scratch
COPY package.json /app/node_modules/syft-cs-fixture/package.json
EOF

# note: the image name deliberately avoids the string "containers-storage" so stderr greps below are unambiguous
image_ref="localhost/syft-cs-fixture:latest"
missing_ref="localhost/syft-cs-missing:latest"

for driver in vfs overlay; do
  store_dir="$test_dir/$driver"
  mkdir -p "$store_dir"
  export CONTAINERS_STORAGE_CONF="$store_dir/storage.conf"
  cat > "$CONTAINERS_STORAGE_CONF" <<EOF
[storage]
driver = "$driver"
graphroot = "$store_dir/graphroot"
rootless_storage_path = "$store_dir/graphroot"
runroot = "$store_dir/runroot"
EOF

  printf 'Building %s with %s (%s driver)\n' "$image_ref" "$builder" "$driver"
  case "$builder" in
    podman)
      podman build --pull=never --tag "$image_ref" "$build_context"
      ;;
    buildah)
      buildah build --pull=false --tag "$image_ref" "$build_context"
      ;;
  esac

  for scan_mode in from-flag scheme default-pull-source; do
    printf 'Testing %s resolution with %s (%s driver)\n' "$scan_mode" "$builder" "$driver"
    out="$store_dir/$scan_mode"
    case "$scan_mode" in
      from-flag)
        run_syft -vv --from containers-storage "$image_ref" --output json > "$out.json" 2> "$out.stderr"
        ;;
      scheme)
        run_syft -vv "containers-storage:$image_ref" --output json > "$out.json" 2> "$out.stderr"
        ;;
      default-pull-source)
        SYFT_SOURCE_IMAGE_DEFAULT_PULL_SOURCE=containers-storage \
          run_syft -vv "$image_ref" --output json > "$out.json" 2> "$out.stderr"
        ;;
    esac

    # prove the image came out of the store, not from some other provider that happened to answer
    if ! grep -q 'copied image from containers-storage' "$out.stderr"; then
      printf 'Expected %s scan to resolve via containers-storage\n' "$scan_mode" >&2
      cat "$out.stderr" >&2
      exit 1
    fi
    jq -e --arg image_ref "$image_ref" '
      .source.type == "image" and
      .source.metadata.userInput == $image_ref and
      any(.artifacts[]; .name == "syft-cs-fixture" and .version == "1.2.3" and .type == "npm")
    ' "$out.json" >/dev/null
  done

  printf 'Testing plain reference skips containers-storage with %s (%s driver)\n' "$builder" "$driver"
  # the image only exists in the local store, so automatic resolution (daemons, then registry) must fail without
  # ever trying containers-storage
  if run_syft "$image_ref" --output json > "$store_dir/plain.json" 2> "$store_dir/plain.stderr"; then
    printf 'Expected plain reference scan to fail since the image only exists in containers-storage\n' >&2
    exit 1
  fi
  if grep -q 'containers-storage' "$store_dir/plain.stderr"; then
    printf 'Plain reference unexpectedly attempted containers-storage resolution\n' >&2
    cat "$store_dir/plain.stderr" >&2
    exit 1
  fi

  printf 'Testing missing image with %s (%s driver)\n' "$builder" "$driver"
  if run_syft --from containers-storage "$missing_ref" --output json > "$store_dir/missing.json" 2> "$store_dir/missing.stderr"; then
    printf 'Expected the missing containers-storage image scan to fail\n' >&2
    exit 1
  fi
  if ! grep -q 'does not resolve to an image ID' "$store_dir/missing.stderr"; then
    printf 'Expected a containers-storage "image not found" error\n' >&2
    cat "$store_dir/missing.stderr" >&2
    exit 1
  fi
done
