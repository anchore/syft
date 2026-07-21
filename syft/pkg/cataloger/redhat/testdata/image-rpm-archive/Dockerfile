
FROM --platform=linux/amd64 rockylinux:9 AS rpm-downloader

# download a signed RPM from the Rocky Linux 9.3 vault. Rocky Linux freezes
# minor-version contents in the vault indefinitely, which gives us a stable
# upstream that won't rotate the way distro "current" repos do (the previous
# fixture used a PostgreSQL repo and broke when PG removed older 14.x RPMs).
#
# $ rpm -Kv basesystem-11-13.el9.0.1.noarch.rpm
#   basesystem-11-13.el9.0.1.noarch.rpm:
#       Header V4 RSA/SHA256 Signature, key ID 350d275d: NOKEY
#       Header SHA256 digest: OK
#       Header SHA1 digest: OK
#       Payload SHA256 digest: OK
#       MD5 digest: OK
#
# $ rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE} %{RSAHEADER:pgpsig}\n' basesystem-11-13.el9.0.1.noarch.rpm
#   basesystem-11-13.el9.0.1 RSA/SHA256, Thu Feb 29 17:37:22 2024, Key ID 702d426d350d275d

RUN curl -O https://dl.rockylinux.org/vault/rocky/9.3/BaseOS/x86_64/os/Packages/b/basesystem-11-13.el9.0.1.noarch.rpm

FROM scratch

COPY --from=rpm-downloader /basesystem-11-13.el9.0.1.noarch.rpm /basesystem-11-13.el9.0.1.noarch.rpm
