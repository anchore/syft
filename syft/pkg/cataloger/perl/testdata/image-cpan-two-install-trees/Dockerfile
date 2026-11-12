# two perl lib trees on one image, each with its own perllocal.pod naming the same module at a
# different version. Picking the stanza from the wrong tree would be silent, and both installed .pm
# files are the real ones, so scraping cannot cover for it: each tree would be reported at the
# other's version.
#
# Both JSON-PP installs come from local tarballs, so neither writes an install.json and the version
# can only come from perllocal.pod. A second full perl is not needed; a local-lib prefix reproduces
# the same ambiguity, because cpanm -L writes a perllocal.pod into the prefix's own arch directory.
#
# The image also carries one distribution installed into both trees at the same version, from a
# mirror, so that both trees hold an install.json agreeing on name and version. Those two records
# describe two installed things and are only distinguishable by the tree they landed in.
#
# The digest is perl:5.40-slim's linux/amd64 manifest; see image-cpan-mirror-installs/Dockerfile.
FROM perl:5.40-slim@sha256:af886c2fe0170cdf0bd83fa8254c7a55da227d5f20988a2e96c836646f96aa7a AS builder

WORKDIR /tarballs
RUN curl -sSfLO https://backpan.perl.org/authors/id/M/MA/MAKAMAKA/JSON-PP-2.27300.tar.gz \
 && curl -sSfLO https://backpan.perl.org/authors/id/I/IS/ISHIGAKI/JSON-PP-4.16.tar.gz

# the site install. 4.16 declares `our $VERSION = '4.16';`, which is scrapable, so this tree is the
# one where perllocal.pod and the .pm agree.
RUN cpanm --notest ./JSON-PP-4.16.tar.gz

# the second tree. 2.27300 declares the fully qualified `$JSON::PP::VERSION = '2.27300';` form that
# older Dist::Zilla wrote.
RUN cpanm --notest -L /opt/app ./JSON-PP-2.27300.tar.gz

# the same distribution and version into both trees. Resolving from a mirror is what makes cpanm
# write an install.json, and the PAUSE path pins the version the way a bare module name would not.
# Text-CSV is pure perl and pulls in nothing that is not core, so this needs no compiler and adds no
# unpinned fetch.
RUN cpanm --notest I/IS/ISHIGAKI/Text-CSV-2.06.tar.gz \
 && cpanm --notest -L /opt/app I/IS/ISHIGAKI/Text-CSV-2.06.tar.gz

RUN mkdir -p /out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu \
 && cp -a /usr/local/lib/perl5/site_perl /out/usr/local/lib/perl5/site_perl \
 && cp -a /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod \
          /usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/.packlist \
          /out/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/ \
 && mkdir -p /out/opt \
 && cp -a /opt/app /out/opt/app

FROM scratch

COPY --from=builder /out/ /
