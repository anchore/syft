FROM rockylinux:8
RUN dnf update -y; \
	dnf install make automake gcc gcc-c++ kernel-devel -y; \
	dnf clean all
RUN mkdir -p /usr/local/bin/elftests/elfbinwithnestedlib
RUN mkdir -p /usr/local/bin/elftests/elfbinwithsisterlib
COPY ./elfbinwithnestedlib /usr/local/bin/elftests/elfbinwithnestedlib
COPY ./elfbinwithsisterlib /usr/local/bin/elftests/elfbinwithsisterlib
ENV LD_LIBRARY_PATH=/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib
WORKDIR /usr/local/bin/elftests/elfbinwithnestedlib/
RUN make
WORKDIR /usr/local/bin/elftests/elfbinwithsisterlib
RUN make

