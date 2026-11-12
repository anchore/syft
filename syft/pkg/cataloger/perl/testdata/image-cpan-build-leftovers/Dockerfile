# an image that installed distributions and did not clean up after itself, which is the ordinary
# state of anything built with a CPAN client: cpanm leaves ~/.cpanm/work and CPAN.pm leaves
# ~/.cpan/build, neither by choice of the user. Both leftovers genuinely are unpacked release
# tarballs, MANIFEST included, so nothing about their contents disqualifies them and they have to be
# excluded on the path.
#
# A release deliberately unpacked outside any build directory sits beside the installed copy of the
# same distribution and version, so the same image shows both halves of the path rule: the leftover
# is skipped and the vendored tree is not.
#
# The digest is perl:5.40-slim's linux/amd64 manifest; see image-cpan-mirror-installs/Dockerfile.
FROM perl:5.40-slim@sha256:af886c2fe0170cdf0bd83fa8254c7a55da227d5f20988a2e96c836646f96aa7a AS builder

# cpanm, mirror-resolved so these carry install.json, and pinned by PAUSE path so the versions do
# not drift. The unpacked build trees are left in /root/.cpanm/work.
RUN cpanm --notest \
      R/RE/REHSACK/MIME-Base32-1.303.tar.gz \
      O/OA/OALDERS/URI-5.35.tar.gz

# CPAN.pm, which writes no .meta and leaves its build tree in /root/.cpan/build under a
# randomly suffixed directory
RUN PERL_MM_USE_DEFAULT=1 cpan -T -i P/PE/PETDANCE/HTML-Tagset-3.24.tar.gz

# the same release, unpacked somewhere a user would keep it on purpose. Nothing pairs this with the
# installed copy: the two come from different catalogers, and two packages found at different
# locations can never share a package ID.
RUN mkdir -p /opt/vendor \
 && curl -sSfL https://backpan.perl.org/authors/id/P/PE/PETDANCE/HTML-Tagset-3.24.tar.gz \
    | tar xz -C /opt/vendor

# the clients' download caches under ~/.cpanm/sources and ~/.cpan/sources are not evidence of
# anything and are the bulk of the bytes, so only the unpacked build trees come along
RUN mkdir -p /out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu /out/root/.cpanm /out/root/.cpan /out/opt \
 && cp -a /usr/local/lib/perl5/site_perl /out/usr/local/lib/perl5/site_perl \
 && cp -a /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod \
          /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/.packlist \
          /out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/ \
 && cp -a /root/.cpanm/work /out/root/.cpanm/work \
 && cp -a /root/.cpan/build /out/root/.cpan/build \
 && cp -a /opt/vendor /out/opt/vendor

FROM scratch

COPY --from=builder /out/ /
