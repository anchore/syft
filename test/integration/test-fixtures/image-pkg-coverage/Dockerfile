FROM fedora:37@sha256:3f987b7657e944cf87a129cc262982d4f80e38bd98f7db313ccaf90ca7069dd2

RUN dnf install 'dnf-command(download)' cpio unzip xz -y
# https://dl.fedoraproject.org/pub/fedora/linux/releases/37/Everything/x86_64/os/Packages/k/kernel-6.0.7-301.fc37.x86_64.rpm
# https://dl.fedoraproject.org/pub/fedora/linux/releases/37/Everything/x86_64/os/Packages/k/kernel-modules-6.0.7-301.fc37.x86_64.rpm
RUN dnf download kernel-core-6.0.7-301.fc37 kernel-modules-6.0.7-301.fc37 -y

RUN rpm2cpio kernel-core-*.rpm | cpio -t && \
    rpm2cpio kernel-core-*.rpm | cpio -idmv ./lib/modules/6.0.7-301.fc37.x86_64/vmlinuz

RUN rpm2cpio kernel-modules-*.rpm | cpio -t && \
    rpm2cpio kernel-modules-*.rpm | cpio -idmv ./lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko.xz

RUN unxz /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko.xz

# dotnet pkg coverage
# https://nuget.info/packages/DocuSign.eSign.dll/6.8.0
# https://github.com/docusign/docusign-esign-csharp-client/blob/master/LICENSE
RUN curl -LO https://www.nuget.org/api/v2/package/DocuSign.eSign.dll/6.8.0
RUN unzip 6.8.0
RUN chmod 600 lib/net462/DocuSign.eSign.dll
RUN rm 6.8.0

FROM scratch

COPY --from=0 lib/net462/DocuSign.eSign.dll .
COPY --from=0 /lib/modules/6.0.7-301.fc37.x86_64/vmlinuz /lib/modules/6.0.7-301.fc37.x86_64/vmlinuz
COPY --from=0 /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko


COPY pkgs/ .
# we duplicate to show a package count difference between all-layers and squashed scopes
COPY lib lib
COPY etc/ .
