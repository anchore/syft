# LAYER 0:
FROM busybox:1.34.0@sha256:e8e5cca392e3cf056fcdb3093e7ac2bf83fcf28b3bcf5818fe8ae71cf360c231

# LAYER 1: a regular file with two hardlinks to it, all created in the same layer so the layer tar contains one
# regular file entry and two hardlink (tar TypeLink) entries pointing at it.
RUN echo "hardlinked contents" > /file.txt && ln /file.txt /hardlink-a && ln /file.txt /hardlink-b

# squash representation (of the files added here; busybox base also contributes hardlinked applets under /bin)
#  .
#  ├── file.txt
#  ├── hardlink-a   (hardlink -> file.txt)
#  └── hardlink-b   (hardlink -> file.txt)
