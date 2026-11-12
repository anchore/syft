// Package perl provides Cataloger implementations relating to CPAN distributions within the Perl
// language ecosystem.
//
// Only distribution-level identity is emitted. Three evidence sources are read: install.json under a
// .meta directory, .packlist paired with perllocal.pod, and an unpacked release's own META.json or
// META.yml alongside a MANIFEST.
//
// The coverage boundary that follows from that:
//
//   - CPAN-client installs are cataloged wherever they live, including local-lib trees such as an
//     application's local/lib/perl5. cpanm, cpm, and carton write install.json only when the
//     distribution was resolved from a mirror; a local directory or tarball install (cpanm .,
//     cpanm ./Foo-1.0.tar.gz) writes none, and those fall back to the packlist pass. CPAN.pm never
//     writes install.json at all.
//   - A packlist is written by the ExtUtils::MakeMaker and Module::Build install targets unless
//     suppressed with NO_PACKLIST, which is what distro packagers set.
//   - A packlist-derived name is the installer's NAME, which is usually but not always the
//     distribution name: libwww-perl installs to auto/LWP/.packlist. Resolving those to
//     distributions is left to the vulnerability data, which carries the mapping.
//   - Perl modules installed from distro packages are not cataloged here. They carry no CPAN-native
//     metadata, since packagers suppress it, and they are already reported by the deb, rpm, and apk
//     catalogers.
//   - Core and dual-life distributions bundled with the interpreter are not cataloged. No on-disk
//     artifact carries their versions. The interpreter itself is reported separately.
//   - Build leftovers under ~/.cpanm/work and ~/.cpan/build are skipped. They are unpacked release
//     tarballs, MANIFEST included, but they describe a copy that is already installed elsewhere in
//     the same tree.
//   - Vendored .pm trees, App::FatPacker output, and PAR archives are invisible. What they carry is
//     module identity, and there is no offline map from a module to the distribution that shipped
//     it. Fatpacked output does embed the .pm sources verbatim, $VERSION lines included, so the
//     missing fact is the distribution rather than the version.
//   - A cpanfile or cpanfile.snapshot is not parsed yet. The snapshot is a resolved lockfile and
//     the only evidence in a source checkout or CI workspace, where local/ does not exist, so it
//     is deferred rather than out of scope.
package perl

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewCpanInstalledCataloger returns a cataloger for CPAN distributions installed on disk.
// Globs are deliberately unanchored so local-lib trees (carton, cpanm -L) are found wherever they live.
func NewCpanInstalledCataloger() pkg.Cataloger {
	return generic.NewCataloger("perl-cpan-installed-cataloger").
		WithParserByGlobs(parseInstallJSON, "**/.meta/*/install.json").
		WithParserByGlobs(parsePacklist, "**/auto/**/.packlist").
		// registration order is execution order, and resolvePacklistVersions has to precede
		// mergeDistributions: merging pairs a packlist package to its install.json package only when the
		// versions agree or the packlist version is absent, so filling versions in afterwards splits every
		// distribution whose two evidence kinds disagree into two packages
		WithResolvingProcessors(resolvePacklistVersions).
		WithProcessors(mergeDistributions).
		WithResolvingProcessors(resolveDependencies)
}

// NewCpanMetaCataloger returns a cataloger for unpacked CPAN releases: release tarballs and vendored
// distribution trees. CPAN client build leftovers are excluded, see isBuildLeftover.
func NewCpanMetaCataloger() pkg.Cataloger {
	return generic.NewCataloger("perl-cpan-meta-cataloger").
		WithParserByGlobs(parseReleaseMeta, "**/META.json", "**/META.yml")
}
