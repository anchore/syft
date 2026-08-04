# release tarballs unpacked but never installed, plus a source repository working tree. Nothing here
# has a packlist or an install.json, so the whole image is meta-file evidence.
#
# Versions are pinned, and pinned versions have to come from backpan: the mirrors drop old releases
# and answer with an HTML 404 that only fails later, at the point of untarring.
#
# The digest is perl:5.40-slim's linux/amd64 manifest rather than its index, so every image in this
# directory is built from the same architecture; see image-cpan-mirror-installs/Dockerfile.
FROM perl:5.40-slim@sha256:af886c2fe0170cdf0bd83fa8254c7a55da227d5f20988a2e96c836646f96aa7a AS builder

WORKDIR /opt/releases

# a Dist::Zilla release: it ships dist.ini inside the tarball, and MANIFEST lists it, so a dist.ini
# beside a META.json says nothing about whether this is a release or a checkout. It also ships both
# META.json and META.yml, which is the ordinary case for dzil and where META.json has to win.
RUN curl -sSfL https://backpan.perl.org/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz | tar xz

# CPAN Meta Spec 1.4, which is all that roughly 43% of current releases ship. Genuine
# ExtUtils::MakeMaker 6.56 output: license is a bare string rather than an array, version is an
# unquoted number, and there is no provides block because EUMM does not generate one.
RUN curl -sSfL https://backpan.perl.org/authors/id/M/MA/MAKAMAKA/Text-CSV-1.21.tar.gz | tar xz

# a META.yml no strict YAML parser accepts: EUMM wrote this distribution's multi-line ABSTRACT
# straight into `abstract:` with no quoting and no block scalar, so the continuation lines land at
# column zero. This has to skip the directory rather than fail the scan.
RUN curl -sSfL https://backpan.perl.org/authors/id/L/LE/LEMBARK/Parallel-Depend-4.10.tar.gz | tar xz

# a source repository working tree, pinned to one commit. Its committed META.json records the last
# release at 6.83 while lib/LWP.pm on the same commit says 6.84, which is why a committed META.json
# cannot be trusted for version. There is no MANIFEST, because Dist::Zilla generates it at build
# time, and that absence is the only thing separating this from a release.
#
# This is GitHub's tarball of the commit rather than a clone: it is the same working tree, it needs
# no git in the image, and it leaves no .git directory to prune.
RUN mkdir -p /src \
 && curl -sSfL https://codeload.github.com/libwww-perl/libwww-perl/tar.gz/65c6384c3d9e8a4f88a7fbe84307895dc78ccceb \
    | tar xz -C /src \
 && mv /src/libwww-perl-* /src/libwww-perl

FROM scratch

COPY --from=builder /opt/releases /opt/releases
COPY --from=builder /src/libwww-perl /src/libwww-perl
