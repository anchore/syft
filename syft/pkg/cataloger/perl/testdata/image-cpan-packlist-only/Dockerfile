# installs that leave a .packlist and no install.json, which is the majority of real Perl images and
# where the interesting failures live: the distribution name has to come out of the auto/ path and
# the version out of perllocal.pod or the installed .pm.
#
# Four real installers are exercised, none of which writes a .meta directory:
#
#   - ExtUtils::MakeMaker run directly (perl Makefile.PL && make install), which is what distro
#     packagers and vendored builds do. It resolves no dependencies at all.
#   - cpanm against a local tarball. cpanm's save_meta returns early unless the distribution was
#     resolved from a mirror, so a local source writes no install.json.
#   - CPAN.pm, which never writes a .meta directory in any circumstance.
#   - an EUMM install with NO_PERLLOCAL, which is the case that forces the version to be scraped out
#     of the installed .pm.
#
# Old versions are pinned and pinned versions come from backpan: the mirrors drop them and answer
# with an HTML 404 body, which only fails later as "gzip: stdin: not in gzip format".
#
# The digest is perl:5.40-slim's linux/amd64 manifest; see image-cpan-mirror-installs/Dockerfile.
FROM perl:5.40-slim@sha256:af886c2fe0170cdf0bd83fa8254c7a55da227d5f20988a2e96c836646f96aa7a AS builder

# Encode is XS and the slim image ships no compiler
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tarballs
RUN curl -sSfLO https://backpan.perl.org/authors/id/G/GA/GAAS/libwww-perl-5.836.tar.gz \
 && curl -sSfLO https://backpan.perl.org/authors/id/I/IS/ISHIGAKI/Text-CSV-2.02.tar.gz \
 && curl -sSfLO https://backpan.perl.org/authors/id/I/IS/ISHIGAKI/Text-CSV-2.06.tar.gz \
 && curl -sSfLO https://backpan.perl.org/authors/id/I/IS/ISHIGAKI/JSON-PP-4.16.tar.gz

# ExtUtils::MakeMaker, run by hand. libwww-perl's EUMM NAME is LWP, so the packlist lands at
# auto/LWP/.packlist and the distribution is only ever recoverable as "LWP" from an installed tree.
# EUMM installs no prerequisites and only warns about the missing ones, which is what keeps this
# image free of the mirror-resolved records those would have written.
RUN tar xzf libwww-perl-5.836.tar.gz \
 && cd libwww-perl-5.836 \
 && perl Makefile.PL \
 && make \
 && make install

# cpanm from a local tarball, twice, upgrading in place. perllocal.pod is append-only, so 2.02's
# stanza stays beside 2.06's forever and the later one has to win.
RUN cpanm --notest ./Text-CSV-2.02.tar.gz \
 && cpanm --notest ./Text-CSV-2.06.tar.gz

# a packlist with no perllocal.pod stanza at all, which is what NO_PERLLOCAL leaves and what
# Module::Build::Tiny produces by default. The version can then only come from the installed .pm.
RUN PERL_MM_OPT="NO_PERLLOCAL=1" cpanm --notest ./JSON-PP-4.16.tar.gz

# CPAN.pm. Encode's $VERSION is declared bare and computed with sprintf from an RCS Revision keyword
# inside a BEGIN block, so no static read of Encode.pm can recover it; only perllocal.pod, which
# records what EUMM evaluated at build time, has the value.
RUN PERL_MM_USE_DEFAULT=1 cpan -T -i D/DA/DANKOGAI/Encode-3.24.tar.gz

# guard the premise of the whole image rather than trusting it
RUN if find /usr/local/lib/perl5 -name install.json | grep -q .; then \
      echo "an install.json was written; this image is supposed to have none"; exit 1; \
    fi

RUN mkdir -p /out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu \
 && cp -a /usr/local/lib/perl5/site_perl /out/usr/local/lib/perl5/site_perl \
 && cp -a /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod \
          /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/.packlist \
          /out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/

FROM scratch

COPY --from=builder /out/ /
