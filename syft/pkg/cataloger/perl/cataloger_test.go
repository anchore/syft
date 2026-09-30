package perl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

// every fixture here is an image built by a Dockerfile under testdata/, one per evidence tier. The
// installs are performed by the real clients inside the image, so the on-disk layout, the file
// contents and the versions are whatever the toolchain actually produced.
//
// an image is only how the fixture is delivered. perl-cpan-meta-cataloger is registered declared and
// directory, never image, so through the CLI it never runs against a container image at all; the tests
// below that drive it through an image resolver are parser tests, and the file tree they read is what
// they are actually asserting on.

// TestCpanInstalledCataloger_mirrorInstalls covers the only case that produces an install.json:
// cpanm, cpm and carton resolving distributions from a mirror. The image installs libwww-perl and its
// whole dependency closure with cpanm, one distribution with NO_PACKLIST, one with carton into an
// application's local/, and one with cpm into an unrelated prefix.
func TestCpanInstalledCataloger_mirrorInstalls(t *testing.T) {
	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-cpan-mirror-installs").
		ExpectsPackageStrings([]string{
			// preinstalled in the base image by its own EUMM installs: a packlist and a perllocal.pod
			// stanza, no .meta, which is why these three have no author qualifier on their purl
			"App-cpanminus @ 1.7049 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/App/cpanminus/.packlist)",
			"IO-Socket-SSL @ 2.099 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/IO/Socket/SSL/.packlist)",
			"Net-SSLeay @ 1.96 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/Net/SSLeay/.packlist)",

			// cpm, into a prefix that is not under /usr, which is the whole reason the globs are unanchored
			"Capture-Tiny @ 0.48 (/srv/api/local/lib/perl5/x86_64-linux-gnu/.meta/Capture-Tiny-0.48/install.json)",

			// carton, into local/lib/perl5 beside the cpanfile
			"Text-CSV @ 2.06 (/app/local/lib/perl5/x86_64-linux-gnu/.meta/Text-CSV-2.06/install.json)",

			// installed with NO_PACKLIST and NO_PERLLOCAL, the way distro packagers do it, so
			// install.json is the only evidence there is
			"JSON-PP @ 4.16 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/JSON-PP-4.16/install.json)",

			// libwww-perl is reported under its distribution name even though install.json's `name` field
			// says LWP and its packlist is auto/LWP/.packlist. There is deliberately no LWP package here:
			// reporting one is the bug this image exists to catch.
			"libwww-perl @ 6.83 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/libwww-perl-6.83/install.json)",

			// the rest of the closure cpanm pulled in for libwww-perl
			"Clone @ 0.50 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/Clone-0.50/install.json)",
			"Encode-Locale @ 1.05 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/Encode-Locale-1.05/install.json)",
			"File-Listing @ 6.16 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/File-Listing-6.16/install.json)",
			"HTML-Parser @ 3.85 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/HTML-Parser-3.85/install.json)",
			"HTML-Tagset @ 3.24 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/HTML-Tagset-3.24/install.json)",
			"HTTP-Cookies @ 6.12 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/HTTP-Cookies-6.12/install.json)",
			"HTTP-Date @ 6.08 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/HTTP-Date-6.08/install.json)",
			"HTTP-Message @ 7.04 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/HTTP-Message-7.04/install.json)",
			"HTTP-Negotiate @ 6.01 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/HTTP-Negotiate-6.01/install.json)",
			"IO-HTML @ 1.004 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/IO-HTML-1.004/install.json)",
			"LWP-MediaTypes @ 6.04 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/LWP-MediaTypes-6.04/install.json)",
			"MIME-Base32 @ 1.303 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/MIME-Base32-1.303/install.json)",
			"Net-HTTP @ 6.24 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/Net-HTTP-6.24/install.json)",
			"TimeDate @ 2.35 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/TimeDate-2.35/install.json)",
			"Try-Tiny @ 0.32 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/Try-Tiny-0.32/install.json)",
			"URI @ 5.35 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/URI-5.35/install.json)",
			"WWW-RobotRules @ 6.03 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/WWW-RobotRules-6.03/install.json)",

			// note: no package for the core perl packlist, which has no auto/ segment, and none for the
			// distributions perllocal.pod names but that have no packlist of their own
		}).
		TestCataloger(t, NewCpanInstalledCataloger())
}

// TestCpanInstalledCataloger_prereqRelationships pins the dependency graph read out of the
// MYMETA.json files cpanm left beside each install.json. Prereqs name modules, so each one has to be
// resolved through the provides map of the cataloged set; a prereq that resolves to nothing (a core
// module such as Carp or strict, or a distribution that is simply not installed) is dropped.
//
// Packages are stringed without their locations here, because the full form makes each relationship
// unreadable.
func TestCpanInstalledCataloger_prereqRelationships(t *testing.T) {
	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-cpan-mirror-installs").
		WithPackageStringer(func(p pkg.Package) string { return p.Name + " @ " + p.Version }).
		ExpectsRelationshipStrings([]string{
			"Clone @ 0.50 [dependency-of] HTTP-Message @ 7.04",
			"Encode-Locale @ 1.05 [dependency-of] HTTP-Message @ 7.04",
			"Encode-Locale @ 1.05 [dependency-of] libwww-perl @ 6.83",
			"File-Listing @ 6.16 [dependency-of] libwww-perl @ 6.83",
			"HTML-Parser @ 3.85 [dependency-of] libwww-perl @ 6.83",
			"HTML-Tagset @ 3.24 [dependency-of] HTML-Parser @ 3.85",
			"HTTP-Cookies @ 6.12 [dependency-of] libwww-perl @ 6.83",
			"HTTP-Date @ 6.08 [dependency-of] File-Listing @ 6.16",
			"HTTP-Date @ 6.08 [dependency-of] HTTP-Cookies @ 6.12",
			"HTTP-Date @ 6.08 [dependency-of] HTTP-Message @ 7.04",
			"HTTP-Date @ 6.08 [dependency-of] libwww-perl @ 6.83",
			"HTTP-Message @ 7.04 [dependency-of] HTML-Parser @ 3.85",
			"HTTP-Message @ 7.04 [dependency-of] HTTP-Cookies @ 6.12",
			"HTTP-Message @ 7.04 [dependency-of] HTTP-Negotiate @ 6.01",
			"HTTP-Message @ 7.04 [dependency-of] libwww-perl @ 6.83",
			"HTTP-Negotiate @ 6.01 [dependency-of] libwww-perl @ 6.83",
			"IO-HTML @ 1.004 [dependency-of] HTTP-Message @ 7.04",
			"LWP-MediaTypes @ 6.04 [dependency-of] HTTP-Message @ 7.04",
			"LWP-MediaTypes @ 6.04 [dependency-of] libwww-perl @ 6.83",
			// URI 5.35 needs MIME::Base32 to build, which is why cpanm installed it at all
			"MIME-Base32 @ 1.303 [dependency-of] URI @ 5.35",
			"Net-HTTP @ 6.24 [dependency-of] libwww-perl @ 6.83",
			// the module TimeDate provides is Date::Format, so this only resolves through the provides map
			"TimeDate @ 2.35 [dependency-of] HTTP-Date @ 6.08",
			"Try-Tiny @ 0.32 [dependency-of] libwww-perl @ 6.83",
			"URI @ 5.35 [dependency-of] HTML-Parser @ 3.85",
			"URI @ 5.35 [dependency-of] HTTP-Message @ 7.04",
			"URI @ 5.35 [dependency-of] Net-HTTP @ 6.24",
			"URI @ 5.35 [dependency-of] WWW-RobotRules @ 6.03",
			"URI @ 5.35 [dependency-of] libwww-perl @ 6.83",
			"WWW-RobotRules @ 6.03 [dependency-of] libwww-perl @ 6.83",
		}).
		TestCataloger(t, NewCpanInstalledCataloger())
}

func TestCpanInstalledCataloger_mirrorInstallEvidence(t *testing.T) {
	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-cpan-mirror-installs").
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			byName := make(map[string]pkg.Package)
			for _, p := range pkgs {
				byName[p.Name] = p
			}

			uri := byName["URI"]
			require.NotEmpty(t, uri.Name)
			assert.Equal(t, "pkg:cpan/URI@5.35?author=OALDERS", uri.PURL)
			assert.Equal(t, pkg.Perl, uri.Language)
			assert.Equal(t, pkg.CpanPkg, uri.Type)

			// licenses come from the MYMETA.json beside install.json, and are not duplicated into
			// metadata. URI's own x_spdx_expression is what reaches the package, not the perl_5 token
			// beside it: the expression is already SPDX, where perl_5 is a CPAN::Meta shortname that
			// would have to be translated.
			require.Len(t, uri.Licenses.ToSlice(), 1)
			assert.Equal(t, "Artistic-1.0-Perl OR GPL-1.0-or-later", uri.Licenses.ToSlice()[0].Value)

			// install.json, its sibling MYMETA.json, the packlist and the perllocal.pod that resolved
			// the packlist's version are all evidence. The main .pm is not: perllocal.pod answered
			// first, so it was never scraped.
			assert.ElementsMatch(t, []string{
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/URI-5.35/install.json",
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/URI-5.35/MYMETA.json",
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/URI/.packlist",
				"/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod",
			}, realPaths(uri))

			// a distribution with no x_spdx_expression falls back to the CPAN::Meta license token
			require.Len(t, byName["Capture-Tiny"].Licenses.ToSlice(), 1)
			assert.Equal(t, "apache_2_0", byName["Capture-Tiny"].Licenses.ToSlice()[0].Value)

			// a packlist-derived package carries no author, so the purl gets no qualifier
			assert.Equal(t, "pkg:cpan/IO-Socket-SSL@2.099", byName["IO-Socket-SSL"].PURL)

			// libwww-perl's packlist is auto/LWP/.packlist, so it shares no (name, version) key with
			// the distribution and is paired through the provides module map instead
			assert.NotContains(t, byName, "LWP", "the module-named packlist must not become its own package")

			lwp := byName["libwww-perl"]
			require.NotEmpty(t, lwp.Name)
			assert.Equal(t, "pkg:cpan/libwww-perl@6.83?author=OALDERS", lwp.PURL)
			assert.ElementsMatch(t, []string{
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/libwww-perl-6.83/install.json",
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/libwww-perl-6.83/MYMETA.json",
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/LWP/.packlist",
				"/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod",
			}, realPaths(lwp))

			// carton's packlist points at the application-local copy, not the site_perl one
			assert.ElementsMatch(t, []string{
				"/app/local/lib/perl5/x86_64-linux-gnu/.meta/Text-CSV-2.06/install.json",
				"/app/local/lib/perl5/x86_64-linux-gnu/.meta/Text-CSV-2.06/MYMETA.json",
				"/app/local/lib/perl5/x86_64-linux-gnu/auto/Text/CSV/.packlist",
				"/app/local/lib/perl5/x86_64-linux-gnu/perllocal.pod",
			}, realPaths(byName["Text-CSV"]))

			// name provenance: Dist records the distvname install.json was read from, MainModule
			// records that the name was inferred from an auto/ path instead. Never both, and a merged
			// package keeps install.json's.
			metadata := func(name string) pkg.CpanDistribution {
				md, ok := byName[name].Metadata.(pkg.CpanDistribution)
				require.True(t, ok, name)
				return md
			}
			assert.Equal(t, "libwww-perl-6.83", metadata("libwww-perl").Dist)
			assert.Empty(t, metadata("libwww-perl").MainModule)
			assert.Equal(t, "IO::Socket::SSL", metadata("IO-Socket-SSL").MainModule)
			assert.Empty(t, metadata("IO-Socket-SSL").Dist)

			// the paths are reported as the packlist recorded them, not filtered to the ones still on
			// disk. IO/Socket/SSL/Utils.pm is deleted in the image on purpose: a path the packlist
			// claims and the filesystem lacks means the file was removed or overwritten, which is
			// exactly what an SBOM consumer wants to see.
			assert.Equal(t, []string{
				"/usr/local/lib/perl5/site_perl/5.40.4/IO/Socket/SSL.pm",
				"/usr/local/lib/perl5/site_perl/5.40.4/IO/Socket/SSL.pod",
				"/usr/local/lib/perl5/site_perl/5.40.4/IO/Socket/SSL/Intercept.pm",
				"/usr/local/lib/perl5/site_perl/5.40.4/IO/Socket/SSL/PublicSuffix.pm",
				"/usr/local/lib/perl5/site_perl/5.40.4/IO/Socket/SSL/Utils.pm",
			}, metadata("IO-Socket-SSL").OwnedFiles())

			// the merge has to carry the packlist's file list onto the install.json package that won,
			// or a merged distribution would own nothing
			assert.Contains(t, metadata("libwww-perl").OwnedFiles(), "/usr/local/lib/perl5/site_perl/5.40.4/LWP.pm")
			assert.Contains(t, metadata("libwww-perl").OwnedFiles(), "/usr/local/bin/lwp-request")

			// NO_PACKLIST leaves an install.json and nothing else, so there is no file list at all
			assert.Empty(t, metadata("JSON-PP").OwnedFiles())
		}).
		TestCataloger(t, NewCpanInstalledCataloger())
}

// TestCpanInstalledCataloger_packlistOnly covers the installs that write no install.json, which is
// the majority of real images and where the version has to come from perllocal.pod or the installed
// .pm. The image runs ExtUtils::MakeMaker directly, cpanm against local tarballs, and CPAN.pm; the
// Dockerfile asserts that none of them left a .meta directory behind.
func TestCpanInstalledCataloger_packlistOnly(t *testing.T) {
	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-cpan-packlist-only").
		ExpectsPackageStrings([]string{
			"App-cpanminus @ 1.7049 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/App/cpanminus/.packlist)",
			// Encode's $VERSION is declared bare and computed with sprintf from an RCS Revision keyword
			// inside a BEGIN block, so nothing static can read it. This version exists only because
			// perllocal.pod records what EUMM evaluated at build time.
			"Encode @ 3.24 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/Encode/.packlist)",
			"IO-Socket-SSL @ 2.099 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/IO/Socket/SSL/.packlist)",
			// installed with NO_PERLLOCAL, so this one had to be scraped out of JSON/PP.pm
			"JSON-PP @ 4.16 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/JSON/PP/.packlist)",
			// libwww-perl's EUMM NAME is LWP, so an installed tree only ever yields "LWP". Resolving
			// that back to the distribution is left to the vulnerability data, which carries the map.
			"LWP @ 5.836 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/LWP/.packlist)",
			"Net-SSLeay @ 1.96 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/Net/SSLeay/.packlist)",
			// installed at 2.02 and then upgraded to 2.06. perllocal.pod is append-only, so both
			// stanzas are still there and the later one has to win.
			"Text-CSV @ 2.06 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/Text/CSV/.packlist)",
		}).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			byName := make(map[string]pkg.Package)
			for _, p := range pkgs {
				byName[p.Name] = p
			}

			// the perllocal.pod that supplied the version is recorded as supporting evidence, and no
			// .pm was read at all
			assert.ElementsMatch(t, []string{
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/Encode/.packlist",
				"/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod",
			}, realPaths(byName["Encode"]))

			// NO_PERLLOCAL wrote no stanza, so the .pm named by the packlist is the evidence instead
			assert.ElementsMatch(t, []string{
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/JSON/PP/.packlist",
				"/usr/local/lib/perl5/site_perl/5.40.4/JSON/PP.pm",
			}, realPaths(byName["JSON-PP"]))

			// no install.json anywhere, so no distribution has an author and no purl has a qualifier
			for _, p := range pkgs {
				assert.NotContains(t, p.PURL, "author=", p.Name)
				assert.Empty(t, p.Licenses.ToSlice(), p.Name)
			}
		}).
		TestCataloger(t, NewCpanInstalledCataloger())
}

// TestCpanInstalledCataloger_twoInstallTrees covers an image carrying two perl lib trees, each with
// its own perllocal.pod naming the same module at a different version. Picking the stanza from the
// wrong tree would be silent, so both are pinned.
//
// The same image installs Text-CSV 2.06 from a mirror into both trees, so both hold an install.json
// agreeing on name and version. Those are two installed things and stay two packages: the tree is
// part of what pairs evidence, not the name and version alone.
func TestCpanInstalledCataloger_twoInstallTrees(t *testing.T) {
	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-cpan-two-install-trees").
		ExpectsPackageStrings([]string{
			"App-cpanminus @ 1.7049 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/App/cpanminus/.packlist)",
			"IO-Socket-SSL @ 2.099 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/IO/Socket/SSL/.packlist)",
			"JSON-PP @ 2.27300 (/opt/app/lib/perl5/x86_64-linux-gnu/auto/JSON/PP/.packlist)",
			"JSON-PP @ 4.16 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/JSON/PP/.packlist)",
			"Net-SSLeay @ 1.96 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/Net/SSLeay/.packlist)",
			"Text-CSV @ 2.06 (/opt/app/lib/perl5/x86_64-linux-gnu/.meta/Text-CSV-2.06/install.json)",
			"Text-CSV @ 2.06 (/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/Text-CSV-2.06/install.json)",
		}).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			byVersion := make(map[string]pkg.Package)
			var textCSV []pkg.Package
			for _, p := range pkgs {
				switch p.Name {
				case "JSON-PP":
					byVersion[p.Version] = p
				case "Text-CSV":
					textCSV = append(textCSV, p)
				}
			}
			require.Len(t, byVersion, 2)

			// each tree's Text-CSV carries only its own tree's evidence, and within a tree the
			// install.json and the packlist still merged into the one package
			require.Len(t, textCSV, 2)
			byTree := make(map[string][]string)
			for _, p := range textCSV {
				byTree[installTree(p)] = realPaths(p)
			}
			require.Len(t, byTree, 2)
			assert.ElementsMatch(t, []string{
				"/opt/app/lib/perl5/x86_64-linux-gnu/.meta/Text-CSV-2.06/install.json",
				"/opt/app/lib/perl5/x86_64-linux-gnu/.meta/Text-CSV-2.06/MYMETA.json",
				"/opt/app/lib/perl5/x86_64-linux-gnu/auto/Text/CSV/.packlist",
				"/opt/app/lib/perl5/x86_64-linux-gnu/perllocal.pod",
			}, byTree["/opt/app/lib/perl5/x86_64-linux-gnu"])
			assert.ElementsMatch(t, []string{
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/Text-CSV-2.06/install.json",
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/Text-CSV-2.06/MYMETA.json",
				"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/Text/CSV/.packlist",
				"/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod",
			}, byTree["/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu"])

			// each tree's version came from that tree's own perllocal.pod. Both installs are of the
			// same module, so without the libdir rule one of these would carry the other's version.
			assert.Contains(t, realPaths(byVersion["2.27300"]), "/opt/app/lib/perl5/x86_64-linux-gnu/perllocal.pod")
			assert.Contains(t, realPaths(byVersion["4.16"]), "/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod")

			// ExtUtils::Packlist merges an existing packlist for the same module when writing a new
			// one, so the local-lib install's packlist genuinely claims the site_perl copy too. The
			// file list is reported as written rather than filtered to the prefix.
			owned := byVersion["2.27300"].Metadata.(pkg.CpanDistribution).OwnedFiles()
			assert.Contains(t, owned, "/opt/app/lib/perl5/JSON/PP.pm")
			assert.Contains(t, owned, "/usr/local/lib/perl5/site_perl/5.40.4/JSON/PP.pm")
		}).
		TestCataloger(t, NewCpanInstalledCataloger())
}

// TestCpanMetaCataloger_unpackedReleases covers release tarballs unpacked but never installed, plus a
// source repository working tree.
func TestCpanMetaCataloger_unpackedReleases(t *testing.T) {
	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-cpan-unpacked-releases").
		ExpectsPackageStrings([]string{
			// CPAN Meta Spec 1.4, which is all that roughly 43% of current releases ship. Genuine EUMM
			// 6.56 output: license is a bare string rather than an array and version is an unquoted
			// number, both of which the lenient field types absorb.
			"Text-CSV @ 1.21 (/opt/releases/Text-CSV-1.21/META.yml)",
			// a Dist::Zilla release, which ships dist.ini inside the tarball and lists it in its own
			// MANIFEST, so a dist.ini beside a META.json says nothing about whether this is a release.
			// It ships both meta files and META.json is reported, once.
			"Try-Tiny @ 0.32 (/opt/releases/Try-Tiny-0.32/META.json)",

			// nothing from /opt/releases/Parallel-Depend-4.10: its META.yml is real EUMM output that no
			// strict YAML parser accepts, because the distribution's multi-line ABSTRACT was written
			// straight into `abstract:` with no quoting and no block scalar. That has to skip the
			// directory, not fail the scan.

			// nothing from /src/libwww-perl either: a committed META.json records the last release and
			// drifts from the working tree (6.83 there against 6.84 in lib/LWP.pm on the same commit).
			// The absence of a MANIFEST is what rejects it, since dzil generates one at build time.
		}).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			byName := make(map[string]pkg.Package)
			for _, p := range pkgs {
				byName[p.Name] = p
			}

			// Try-Tiny's META.json carries an x_spdx_expression, which is preferred over the
			// license token beside it
			require.Len(t, byName["Try-Tiny"].Licenses.ToSlice(), 1)
			assert.Equal(t, "MIT", byName["Try-Tiny"].Licenses.ToSlice()[0].Value)

			// spec 1.4 has no x_spdx_expression, so the bare license string is what is left
			require.Len(t, byName["Text-CSV"].Licenses.ToSlice(), 1)
			assert.Equal(t, "perl", byName["Text-CSV"].Licenses.ToSlice()[0].Value)
		}).
		TestCataloger(t, NewCpanMetaCataloger())
}

// TestCpanCatalogers_buildLeftoversAndVendoredRelease covers the ordinary state of any tree that
// installed distributions and did not clean up after itself: cpanm leaves ~/.cpanm/work and CPAN.pm
// leaves ~/.cpan/build, neither by choice of the user.
//
// Both leftovers genuinely are unpacked release tarballs, MANIFEST included, so the sibling-MANIFEST
// gate is working correctly and still admits them. They have to be excluded on the path instead, or
// every distribution in such a tree is reported twice: once from its installed evidence and once from
// the copy the client unpacked to build it. Both catalogers are registered for directory scans, so
// that is where the duplication would be user-visible.
//
// The same fixture carries a release deliberately unpacked under /opt/vendor, which is the other half
// of the path rule and is reported. It is the same distribution and version as the installed copy,
// and it produces a second package rather than merging, for the reason
// TestCpanCatalogers_vendoredReleaseCannotMerge documents.
func TestCpanCatalogers_buildLeftoversAndVendoredRelease(t *testing.T) {
	found := catalogBoth(t, "image-cpan-build-leftovers")

	var names []string
	for _, p := range found {
		names = append(names, p.Name+" @ "+p.Version+" ("+p.FoundBy+")")
	}

	// ElementsMatch rather than Equal: the two HTML-Tagset packages agree on name and version, so
	// pkg.Collection.Sorted breaks the tie on package ID, which is a structural hash and not something
	// worth pinning
	assert.ElementsMatch(t, []string{
		"App-cpanminus @ 1.7049 (perl-cpan-installed-cataloger)",
		"HTML-Tagset @ 3.24 (perl-cpan-installed-cataloger)",
		"HTML-Tagset @ 3.24 (perl-cpan-meta-cataloger)",
		"IO-Socket-SSL @ 2.099 (perl-cpan-installed-cataloger)",
		"MIME-Base32 @ 1.303 (perl-cpan-installed-cataloger)",
		"Net-SSLeay @ 1.96 (perl-cpan-installed-cataloger)",
		"URI @ 5.35 (perl-cpan-installed-cataloger)",
	}, names, "each installed distribution is reported once, nothing comes from the leftover trees, and the vendored copy is reported separately")
}

// TestCpanCatalogers_vendoredReleaseCannotMerge asserts what happens when a release deliberately
// unpacked outside any build directory sits beside the installed copy of the same distribution and
// version.
//
// The intuitive expectation is one package carrying both locations as evidence. That cannot hold, and
// this test pins the real behavior at two packages rather than asserting the intuition and failing.
//
// Why: the two packages come from two different catalogers, so nothing inside either cataloger can
// pair them. mergeDistributions only ever sees one cataloger's output. The only cross-cataloger merge
// syft has is pkg.Collection.add, at syft/pkg/collection.go:119, which merges on artifact.ID equality
// alone. artifact.ID is a structural hash of the whole Package (syft/pkg/package.go:58, via
// artifact.IDByHash), and Locations is a hashed field: the `hash:"ignore"` tags at
// syft/pkg/package.go:30-51 exempt FoundBy, Language, CPEs, and PURL, but not Locations, Licenses, or
// Metadata. Two packages whose locations differ therefore cannot have the same ID, and two packages
// found at the same location are the same evidence and not this case at all. So "same identity,
// merged locations" is unreachable by construction, for any pair of catalogers, not just these two.
func TestCpanCatalogers_vendoredReleaseCannotMerge(t *testing.T) {
	var installed, unpacked pkg.Package
	for _, p := range catalogBoth(t, "image-cpan-build-leftovers") {
		if p.Name != "HTML-Tagset" {
			continue
		}
		// the two agree on name and version, so the duplication is visible and consistent
		assert.Equal(t, "3.24", p.Version)
		assert.Equal(t, "pkg:cpan/HTML-Tagset@3.24", p.PURL)

		switch p.FoundBy {
		case "perl-cpan-installed-cataloger":
			installed = p
		case "perl-cpan-meta-cataloger":
			unpacked = p
		}
	}
	require.NotEmpty(t, installed.Name)
	require.NotEmpty(t, unpacked.Name)

	assert.ElementsMatch(t, []string{
		"/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/auto/HTML/Tagset/.packlist",
		"/usr/local/lib/perl5/5.40.4/x86_64-linux-gnu/perllocal.pod",
	}, realPaths(installed))
	assert.ElementsMatch(t, []string{
		"/opt/vendor/HTML-Tagset-3.24/META.json",
	}, realPaths(unpacked))

	// Locations, Licenses and Metadata are the whole of the difference here, and every other differing
	// field (FoundBy, PURL, CPEs) is `hash:"ignore"`. Overwriting just those three hashed fields makes
	// the IDs equal, which is the direct demonstration of what keeps the two packages apart.
	require.NotEqual(t, installed.ID(), unpacked.ID())
	assert.Empty(t, installed.Licenses.ToSlice(), "a packlist carries no license")
	assert.Equal(t, "artistic_2", unpacked.Licenses.ToSlice()[0].Value, "META.json does, so Licenses differs too")

	relocated := unpacked
	relocated.Locations = installed.Locations
	relocated.Licenses = installed.Licenses
	relocated.Metadata = installed.Metadata
	relocated.SetID()
	assert.Equal(t, installed.ID(), relocated.ID(), "with the hashed fields equalized the IDs match, and only then")
}

// TestCpanCatalogers_coreDistributionsNotCataloged pins the zero coverage of distributions bundled
// inside the interpreter, which the package doc comment states as a gap.
//
// The image is a perl with no CPAN installs at all: Encode and Storable sit in the core lib tree, the
// only packlist is perl's own and has no auto/ segment, and there is no .meta and no distro package.
// Nothing on disk carries a core distribution's version.
//
// Storable.pm does declare a readable $VERSION, so the interesting half is that no package is
// invented from it, and neither is one invented from the perllocal.pod stanzas that name the
// distributions the base image preinstalled into a site_perl this image does not have. The
// interpreter's version is never used as a stopgap either: a distribution name carrying a wrong or
// absent version matches either everything or nothing in an advisory range, which is worse than the
// gap. Closing this needs a generated Module::CoreList table keyed by perl version.
func TestCpanCatalogers_coreDistributionsNotCataloged(t *testing.T) {
	assert.Empty(t, catalogBoth(t, "image-perl-core-only"))
}

// TestCpanCatalogers_metadataTypes pins the metadata type each cataloger emits along with the JSON
// name it serializes as. Both are user-visible API: a consumer decides whether a finding is installed
// and loadable or merely unpacked on disk from the type name, and must not have to string match
// FoundBy.
func TestCpanCatalogers_metadataTypes(t *testing.T) {
	installed := catalogImage(t, "image-cpan-mirror-installs", NewCpanInstalledCataloger())
	unpacked := catalogImage(t, "image-cpan-unpacked-releases", NewCpanMetaCataloger())

	require.NotEmpty(t, installed)
	for _, p := range installed {
		assert.IsType(t, pkg.CpanDistribution{}, p.Metadata, p.Name)
		assert.Equal(t, "cpan-distribution", packagemetadata.JSONName(p.Metadata), p.Name)
	}

	require.NotEmpty(t, unpacked)
	for _, p := range unpacked {
		assert.IsType(t, pkg.CpanUnpackedRelease{}, p.Metadata, p.Name)
		assert.Equal(t, "cpan-unpacked-release", packagemetadata.JSONName(p.Metadata), p.Name)
	}
}

// imageResolver resolves an image fixture the way pkgtest's WithImageResolver does, for the tests
// that need the resolver itself rather than the CatalogTester around it.
func imageResolver(t *testing.T, fixture string) file.Resolver {
	t.Helper()

	img := imagetest.GetFixtureImage(t, "docker-archive", fixture)
	resolver, err := stereoscopesource.New(img, stereoscopesource.ImageConfig{Reference: fixture}).
		FileResolver(source.SquashedScope)
	require.NoError(t, err)

	return resolver
}

func catalogImage(t *testing.T, fixture string, cataloger pkg.Cataloger) []pkg.Package {
	t.Helper()

	pkgs, _, err := cataloger.Catalog(pkgtest.Context(t), imageResolver(t, fixture))
	require.NoError(t, err)

	return pkgs
}

// catalogBoth runs both catalogers over one image and aggregates into a pkg.Collection, which is what
// the real cataloging pipeline does, so any cross-cataloger merge that production performs happens
// here too.
func catalogBoth(t *testing.T, fixture string) []pkg.Package {
	t.Helper()

	resolver := imageResolver(t, fixture)

	collection := pkg.NewCollection()
	for _, cataloger := range []pkg.Cataloger{NewCpanInstalledCataloger(), NewCpanMetaCataloger()} {
		pkgs, _, err := cataloger.Catalog(pkgtest.Context(t), resolver)
		require.NoError(t, err)
		collection.Add(pkgs...)
	}

	return collection.Sorted()
}

func realPaths(p pkg.Package) []string {
	var paths []string
	for _, l := range p.Locations.ToSlice() {
		paths = append(paths, l.RealPath)
	}
	return paths
}
