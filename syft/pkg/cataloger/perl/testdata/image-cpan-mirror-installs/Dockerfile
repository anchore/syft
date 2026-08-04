# mirror-resolved CPAN client installs: cpanm, cpm and carton. This is the only case where an
# install.json is written, so it is also the only image carrying MYMETA.json and a `provides` map.
#
# The digest is perl:5.40-slim's linux/amd64 manifest rather than its index, which pins the
# architecture as well as the contents: perl's lib layout embeds the arch name
# (.../5.40.4/x86_64-linux-gnu/), so a build on an arm host would move every path under test.
FROM perl:5.40-slim@sha256:af886c2fe0170cdf0bd83fa8254c7a55da227d5f20988a2e96c836646f96aa7a AS builder

# Clone and HTML::Parser are XS and the slim image ships no compiler
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# cpm and carton go into a throwaway prefix: their own dependency trees are large and are not under
# test, and nothing from /tools reaches the final image
RUN cpanm --notest --quiet -L /tools App::cpm Carton

# cpanm, site install of libwww-perl and its whole dependency closure.
#
# LWP is the module name; the distribution is libwww-perl, so this is the name mismatch that makes
# install.json's `name` field unusable as a package name, and it installs to auto/LWP/.packlist
# rather than auto/libwww-perl/. The closure comes along on purpose: it is what gives the image real
# MYMETA.json prereqs to resolve into relationships.
#
# Every distribution is named by its PAUSE path, which is what pins the version. A bare module name
# resolves to whatever the index says today, so the closure would drift the moment any of these
# authors releases again. cpanm still treats a PAUSE path as a mirror resolution, so install.json is
# written for all of them, which a URL or a local tarball would not do. Dependencies come first so
# that nothing in the list is ever satisfied by an unpinned fetch.
RUN cpanm --notest \
      E/ET/ETHER/Try-Tiny-0.32.tar.gz \
      A/AT/ATOOMIC/Clone-0.50.tar.gz \
      G/GA/GAAS/Encode-Locale-1.05.tar.gz \
      P/PE/PETDANCE/HTML-Tagset-3.24.tar.gz \
      C/CJ/CJM/IO-HTML-1.004.tar.gz \
      O/OA/OALDERS/LWP-MediaTypes-6.04.tar.gz \
      R/RE/REHSACK/MIME-Base32-1.303.tar.gz \
      A/AT/ATOOMIC/TimeDate-2.35.tar.gz \
      O/OA/OALDERS/URI-5.35.tar.gz \
      O/OA/OALDERS/HTTP-Date-6.08.tar.gz \
      O/OA/OALDERS/HTTP-Message-7.04.tar.gz \
      O/OA/OALDERS/HTML-Parser-3.85.tar.gz \
      P/PL/PLICEASE/File-Listing-6.16.tar.gz \
      O/OA/OALDERS/HTTP-Cookies-6.12.tar.gz \
      G/GA/GAAS/HTTP-Negotiate-6.01.tar.gz \
      O/OA/OALDERS/Net-HTTP-6.24.tar.gz \
      O/OA/OALDERS/WWW-RobotRules-6.03.tar.gz \
      O/OA/OALDERS/libwww-perl-6.83.tar.gz

# a distribution installed the way distro packagers do it: install.json and no packlist at all.
# NO_PACKLIST and NO_PERLLOCAL are ExtUtils::MakeMaker knobs, so this has to be an EUMM
# distribution; a Module::Build::Tiny one would ignore both and write its packlist anyway.
RUN PERL_MM_OPT="NO_PACKLIST=1 NO_PERLLOCAL=1" cpanm --notest I/IS/ISHIGAKI/JSON-PP-4.16.tar.gz

# carton, writing local/lib/perl5 beside the cpanfile it read. The cpanfile and cpanfile.snapshot
# are deliberately left in place and deliberately not parsed by the cataloger.
RUN mkdir -p /app \
 && printf "requires 'Text::CSV', '== 2.06';\n" > /app/cpanfile \
 && cd /app \
 && PERL5LIB=/tools/lib/perl5 PATH=/tools/bin:$PATH carton install

# cpm, into an arbitrary prefix. cpm serializes install.json differently from cpanm (canonical JSON,
# three-space indent, spaces around the colons, trailing newline) and that difference is under test.
RUN PERL5LIB=/tools/lib/perl5 /tools/bin/cpm install -L /srv/api/local --no-test 'Capture::Tiny@0.48'

# a path a packlist claims and the filesystem lacks is what an overwritten or removed file looks
# like, and the owned-file list is expected to report it anyway
RUN rm /usr/local/lib/perl5/site_perl/5.40.4/IO/Socket/SSL/Utils.pm

# assemble only what the catalogers read: the site_perl tree, the core arch directory's
# perllocal.pod and packlist, and the two local-lib trees. The rest of the core lib tree is tens of
# megabytes of interpreter that carries no CPAN evidence.
RUN mkdir -p /out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu \
 && cp -a /usr/local/lib/perl5/site_perl /out/usr/local/lib/perl5/site_perl \
 && cp -a /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod \
          /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/.packlist \
          /out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/ \
 && mkdir -p /out/app /out/srv/api \
 && cp -a /app/cpanfile /app/cpanfile.snapshot /app/local /out/app/ \
 && cp -a /srv/api/local /out/srv/api/local

FROM scratch

COPY --from=builder /out/ /
