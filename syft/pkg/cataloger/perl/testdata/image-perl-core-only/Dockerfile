# a perl with no CPAN installs at all, which pins the zero coverage of distributions bundled inside
# the interpreter. site_perl is dropped entirely, so what is left is the core lib tree: Encode and
# Storable sit in it, the only packlist is perl's own and has no auto/ segment, and there is no
# .meta and no distro package. Nothing here carries a core distribution's version.
#
# perllocal.pod comes along even though it names the distributions the base image preinstalled,
# because a perllocal.pod stanza on its own must not invent a package. Storable.pm does declare a
# readable $VERSION, so the interesting half is that no package is made out of it either.
#
# The digest is perl:5.40-slim's linux/amd64 manifest; see image-cpan-mirror-installs/Dockerfile.
FROM perl:5.40-slim@sha256:af886c2fe0170cdf0bd83fa8254c7a55da227d5f20988a2e96c836646f96aa7a AS builder

# the whole core lib tree is tens of megabytes of interpreter, so this takes the two dual-life
# distributions under discussion, their shared libraries, and the two files the catalogers look for
RUN O=/out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu \
 && mkdir -p $O/auto/Encode $O/auto/Storable \
 && cd /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu \
 && cp -a Encode.pm Storable.pm perllocal.pod .packlist $O/ \
 && cp -a auto/Encode/Encode.so $O/auto/Encode/ \
 && cp -a auto/Storable/Storable.so $O/auto/Storable/

FROM scratch

COPY --from=builder /out/ /
