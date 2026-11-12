FROM gcc:9.5.0

# bullseye is EOL: deb.debian.org dropped it, so pull from archive.debian.org (whose Release files are
# permanently expired, hence Check-Valid-Until). bullseye-security is deliberately omitted -- its index is
# still served but the pool behind it 404s, and it has not been moved to the archive yet. These are throwaway
# fixture build tools, so base bullseye package versions are fine.
RUN printf 'deb http://archive.debian.org/debian bullseye main\ndeb http://archive.debian.org/debian bullseye-updates main\n' > /etc/apt/sources.list \
    && apt -o Acquire::Check-Valid-Until=false update -y \
    && apt install -y clang cmake git make m4 pkg-config zlib1g-dev

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

RUN curl -f -o /bin/checksec https://raw.githubusercontent.com/slimm609/checksec.sh/2.6.0/checksec && chmod +x /bin/checksec
