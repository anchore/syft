FROM gcc:9.5.0

RUN apt update -y && apt install -y clang cmake git make m4 pkg-config zlib1g-dev

## from https://github.com/runsafesecurity/selfrando/blob/tb-v0.4.2/docs/linux-build-instructions.md
#RUN git clone https://github.com/runsafesecurity/selfrando.git && \
#    export SR_ARCH=`uname -m | sed s/i686/x86/` && \
#    cd selfrando && \
#    cmake . -DSR_DEBUG_LEVEL=env -DCMAKE_BUILD_TYPE=Release -DSR_BUILD_LIBELF=1 \
#      -DSR_ARCH=$SR_ARCH -DSR_LOG=console \
#      -DSR_FORCE_INPLACE=1 -G "Unix Makefiles" \
#      -DCMAKE_INSTALL_PREFIX:PATH=$PWD/out/$SR_ARCH
#RUN cd selfrando && make -j`nprocs --all`
#RUN cd selfrando && make install

RUN curl -o /bin/checksec https://raw.githubusercontent.com/slimm609/checksec.sh/2.6.0/checksec && chmod +x /bin/checksec
