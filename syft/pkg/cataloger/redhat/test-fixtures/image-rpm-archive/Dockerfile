
FROM --platform=linux/amd64 rockylinux:9 AS rpm-downloader

# download a signed RPM (PostgreSQL in this example, known to be signed)
# using PostgreSQL official RPM which is signed with their GPG key
# $ rpm -Kv postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm
#   postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm:
#      Header V4 RSA/SHA256 Signature, key ID 08b40d20: NOKEY
#      Header SHA256 digest: OK
#      Header SHA1 digest: OK
#      Payload SHA256 digest: OK
#      MD5 digest: OK
#
# $ rpm -ivh --nodeps --force postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm
#   warning: postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm: Header V4 RSA/SHA256 Signature, key ID 08b40d20: NOKEY
#   Verifying...                          ################################# [100%]
#   Preparing...                          ################################# [100%]
#
# $ rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} %{RSAHEADER:pgpsig}\n' postgresql14-server-14.10-1PGDG.rhel9.x86_64
#   postgresql14-server-14.10-1PGDG.rhel9 RSA/SHA256, Tue Jan  2 16:45:56 2024, Key ID 40bca2b408b40d20

RUN curl -O https://download.postgresql.org/pub/repos/yum/14/redhat/rhel-9-x86_64/postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm

FROM scratch

COPY --from=rpm-downloader /postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm /postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm