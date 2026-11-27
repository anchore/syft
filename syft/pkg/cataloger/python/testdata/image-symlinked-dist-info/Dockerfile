# mimics a Nix-built python environment: each package lives in its own store path and the
# environment's site-packages directory only contains symlinks to the per-package dist-info dirs
# (symlinks are preserved by COPY). see https://github.com/anchore/syft/issues/5643
FROM scratch
COPY nix /nix
