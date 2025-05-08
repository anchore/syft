FROM registry.suse.com/suse/sle15:15.3.17.20.20@sha256:fd657ecbab5ca564d6933e887f6ae8542a9398e6a4b399f352ce10c3a24afc64 AS base
RUN zypper in -y wget

# let's save some space... we really just need an image that has an RPM DB that is linked across layers
FROM --platform=linux/amd64 busybox:1.36.1

# setup a link /var/lib/rpm -> ../../usr/lib/sysimage/rpm
RUN mkdir -p /var/lib && ln -s ../../usr/lib/sysimage/rpm /var/lib/rpm

# copy the RPM DB from the SUSE image
COPY --from=base /usr/lib/sysimage/rpm/Packages.db /usr/lib/sysimage/rpm/Packages.db
