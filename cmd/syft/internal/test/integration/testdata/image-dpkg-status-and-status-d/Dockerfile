# verbatim dpkg records from a Docker Hardened Images Debian 13 image, which lists installed packages in both
# /var/lib/dpkg/status.d/<name> and /var/lib/dpkg/status. The status file is written by two layers (the second adds
# tzdata) so that it is seen more than once when every layer is cataloged.
FROM scratch
COPY packages/ /
COPY status-base/ /
COPY status-updated/ /
