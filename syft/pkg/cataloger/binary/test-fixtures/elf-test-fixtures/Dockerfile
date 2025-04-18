FROM rockylinux:8 AS base

RUN dnf update -y; \
	dnf install make automake gcc gcc-c++ kernel-devel -y; \
	dnf clean all
RUN mkdir -p /usr/local/bin/elftests/elfbinwithnestedlib
RUN mkdir -p /usr/local/bin/elftests/elfbinwithsisterlib
RUN mkdir -p /usr/local/bin/elftests/elfbinwithcorrupt

COPY ./elfbinwithnestedlib /usr/local/bin/elftests/elfbinwithnestedlib
COPY ./elfbinwithsisterlib /usr/local/bin/elftests/elfbinwithsisterlib
COPY ./elfbinwithcorrupt /usr/local/bin/elftests/elfbinwithcorrupt

ENV LD_LIBRARY_PATH=/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib

WORKDIR /usr/local/bin/elftests/elfbinwithnestedlib/
RUN make

WORKDIR /usr/local/bin/elftests/elfbinwithsisterlib
RUN make
WORKDIR /usr/local/bin/elftests/elfbinwithcorrupt
RUN make

# let's make the test image smaller, since we only require the built binaries and supporting libraries
FROM busybox:1.36.1-musl

COPY --from=base /usr/local/bin/elftests /usr/local/bin/elftests
COPY --from=base /var/lib/rpm /var/lib/rpm
COPY --from=base '/usr/lib64/libstdc++.so.6.0.25' '/usr/lib64/libstdc++.so.6.0.25'
COPY --from=base '/usr/lib64/libstdc++.so.6' '/usr/lib64/libstdc++.so.6'
COPY --from=base '/usr/lib64/libc.so.6' '/usr/lib64/libc.so.6'
COPY --from=base '/usr/lib64/libc.so' '/usr/lib64/libc.so'

# prove we can operate over symlinks (/lib64 -> usr/lib64)
RUN ln -s /usr/lib64 /lib64
