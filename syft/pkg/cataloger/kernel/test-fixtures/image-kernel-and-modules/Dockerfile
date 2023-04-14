FROM fedora:37@sha256:3f987b7657e944cf87a129cc262982d4f80e38bd98f7db313ccaf90ca7069dd2

RUN dnf install 'dnf-command(download)' cpio xz -y
RUN dnf download kernel-core kernel-modules-core -y

RUN rpm2cpio kernel-core-*.rpm | cpio -t && \
    rpm2cpio kernel-core-*.rpm | cpio -idmv ./lib/modules/6.2.9-200.fc37.x86_64/vmlinuz

RUN rpm2cpio kernel-modules-core-*.rpm | cpio -t && \
    rpm2cpio kernel-modules-core-*.rpm | cpio -idmv ./lib/modules/6.2.9-200.fc37.x86_64/kernel/drivers/usb/typec/mux/fsa4480.ko.xz

RUN unxz /lib/modules/6.2.9-200.fc37.x86_64/kernel/drivers/usb/typec/mux/fsa4480.ko.xz

FROM scratch

COPY --from=0 /lib/modules/6.2.9-200.fc37.x86_64/vmlinuz /lib/modules/6.2.9-200.fc37.x86_64/vmlinuz
COPY --from=0 /lib/modules/6.2.9-200.fc37.x86_64/kernel/drivers/usb/typec/mux/fsa4480.ko /lib/modules/6.2.9-200.fc37.x86_64/kernel/drivers/usb/typec/mux/fsa4480.ko
