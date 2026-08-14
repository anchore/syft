package perl

import (
	"context"
	"path"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseReleaseMeta catalogs the single distribution described by the META.json or META.yml at the root of
// an unpacked CPAN distribution: a release tarball or a vendored distribution tree.
//
// Both formats are read because META.json is not the common case. Measured on MetaCPAN's file index over
// 41,722 latest releases, root level only: 23,714 ship a META.json (57%), 37,114 a META.yml (89%), and
// 41,008 a MANIFEST (98%). Reading only META.json skips roughly 43% of current releases, skewed toward the
// old ones where the advisories concentrate.
func parseReleaseMeta(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	if isBuildLeftover(reader.Path()) || !isUnpackedRelease(resolver, reader.Location) {
		return nil, nil, nil
	}

	isYAML := strings.EqualFold(path.Base(reader.Path()), "META.yml")

	// where both sit in one directory the META.yml invocation yields nothing. META.json is the spec 2
	// document and is what release tooling generates last, so where they disagree it is the newer
	// rendering. Skipping at this end keeps the cataloger free of dedup processors.
	if isYAML && hasSiblingMetaJSON(resolver, reader.Location) {
		return nil, nil, nil
	}

	decoder := decodeMeta
	if isYAML {
		decoder = decodeMetaYAML
	}

	m, err := decoder(resolver, reader.Location)
	if err != nil {
		// a META.yml a strict parser rejects is routine rather than exceptional, so this skips the
		// directory and never fails the scan
		log.WithFields("path", reader.Path(), "error", err).Debug("unable to parse CPAN meta file")
		return nil, nil, nil
	}

	if m.Name == "" || m.Version == "" {
		log.WithFields("path", reader.Path()).Debug("CPAN meta file is missing a name or version")
		return nil, nil, nil
	}

	location := reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)
	licenses := pkg.NewLicensesFromLocationWithContext(ctx, reader.Location, m.licenseExpressions()...)
	md := pkg.CpanUnpackedRelease{Modules: modulesFromProvides(m.Provides)}

	return []pkg.Package{newCpanPackage(m.Name, string(m.Version), "", md, licenses, location)}, nil, nil
}

// isUnpackedRelease decides whether a meta file describes an unpacked distribution or a source
// repository. A committed META.json records the last release and drifts from the working tree
// (libwww-perl carries 6.83 in META.json and 6.84 in lib/LWP.pm on the same commit), so it must not be
// trusted for version. A sibling MANIFEST is what tells the two apart: release tarballs ship one, while a
// source checkout does not, since the MANIFEST is generated at build time.
func isUnpackedRelease(resolver file.Resolver, metaLocation file.Location) bool {
	_, ok := findFile(resolver, path.Join(path.Dir(metaLocation.Path()), "MANIFEST"))

	return ok
}

// buildLeftoverDirs are the trees CPAN clients unpack into. A cpanm work directory genuinely is an
// unpacked release tarball, MANIFEST included, so the isUnpackedRelease gate is working correctly and
// still admits it; a path exclusion is the only signal available. What makes it a leftover is that a copy
// of the same distribution was installed elsewhere in the same tree, and the two would be reported as
// separate packages, since two catalogers reporting at different locations can never share a package ID.
// Both catalogers run on directory scans, so that duplication is reachable there.
//
// cpanm leaves ~/.cpanm/work/<epoch>/<Dist>-<Version>/ and CPAN.pm leaves
// ~/.cpan/build/<Dist>-<Version>-XXXX/ with a random suffix, neither of which is cleaned up by default,
// so any tree that did not rm -rf them reported every distribution it installed twice.
//
// The honest cost: an unpacked tarball a user deliberately keeps under ~/.cpan/build stops being reported.
var buildLeftoverDirs = []string{".cpanm/work", ".cpan/build"}

func isBuildLeftover(p string) bool {
	normalized := normalizePath(p)
	for _, dir := range buildLeftoverDirs {
		if strings.Contains(normalized, "/"+dir+"/") {
			return true
		}
	}
	return false
}

func hasSiblingMetaJSON(resolver file.Resolver, metaLocation file.Location) bool {
	_, ok := findFile(resolver, path.Join(path.Dir(metaLocation.Path()), "META.json"))

	return ok
}
