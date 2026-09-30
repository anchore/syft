package perl

import (
	"context"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// installJSON is the record cpanm (>= 1.5000), cpm, and carton write for every distribution they install.
type installJSON struct {
	// Name is the MODULE name, not the distribution: libwww-perl records "LWP" here, and
	// CPAN-02Packages-Search records "CPAN::02Packages::Search". It is never the package name.
	Name     string                   `json:"name"`
	Dist     string                   `json:"dist"` // distribution with version, e.g. libwww-perl-5.836
	Version  scalar                   `json:"version"`
	Pathname string                   `json:"pathname"` // PAUSE path, e.g. O/OA/OALDERS/URI-5.35.tar.gz
	Provides map[string]providesEntry `json:"provides"`
}

func parseInstallJSON(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var doc installJSON
	if err := json.NewDecoder(reader).Decode(&doc); err != nil {
		log.WithFields("path", reader.Path(), "error", err).Debug("unable to parse CPAN install.json")
		return nil, nil, nil
	}

	name, version := distributionNameVersion(doc)
	if name == "" || version == "" {
		log.WithFields("path", reader.Path()).Debug("CPAN install.json is missing a distribution name or version")
		return nil, nil, nil
	}

	locations := []file.Location{reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)}

	var licenses []pkg.License
	if myMetaLocation, myMeta := readMyMeta(resolver, reader.Location); myMeta != nil {
		licenses = pkg.NewLicensesFromLocationWithContext(ctx, *myMetaLocation, myMeta.licenseExpressions()...)
		locations = append(locations, myMetaLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	}

	md := pkg.CpanDistribution{
		Dist:    doc.Dist,
		Author:  authorFromPathname(doc.Pathname),
		Path:    doc.Pathname,
		Modules: modulesFromProvides(doc.Provides),
	}

	return []pkg.Package{newCpanPackage(name, version, md.Author, md, licenses, locations...)}, nil, nil
}

// distributionNameVersion resolves the distribution name and version, which every consumer of these
// packages is keyed by. The `name` field cannot be used: it holds the module name, so libwww-perl would
// be reported as LWP and CGI-Session as CGI::Session, which no advisory or index is filed against.
//
// Both come from `dist` rather than trimming `version` off it, because cpanm writes the main module's
// $VERSION into `version` and the release's distvname into `dist`, and the two often disagree:
// Carp-Assert-More-2.9.0 records version 2.009000, and Class-Rebirth-1.003 records 1.000. Trimming fails
// on those, and the resulting version would never pair with the packlist record for the same install.
func distributionNameVersion(doc installJSON) (string, string) {
	distvname := doc.Dist
	if distvname == "" {
		// older cpanm and hand-rolled records omit dist; the PAUSE path basename carries the same
		// <Dist>-<Version>.tar.gz shape
		distvname = distvnameFromPathname(doc.Pathname)
	}

	if name, version := splitDistvname(distvname); name != "" {
		return name, version
	}

	// no version suffix to split off, so dist is already the bare name
	return distvname, string(doc.Version)
}

// distvnamePattern splits a distvname at the last dash followed by a version, the rule
// CPAN::DistnameInfo applies. A -TRIAL suffix is a maturity flag and not part of either half: MetaCPAN
// files Try-Tiny-0.26-TRIAL as distribution Try-Tiny, version 0.26.
var distvnamePattern = regexp.MustCompile(`^(.+)-(v?[0-9][^-]*)(?:-TRIAL[0-9]*)?$`)

func splitDistvname(distvname string) (string, string) {
	match := distvnamePattern.FindStringSubmatch(distvname)
	if match == nil {
		return "", ""
	}
	return match[1], match[2]
}

// distvnameFromPathname recovers the distvname from a PAUSE path such as
// G/GA/GAAS/libwww-perl-5.836.tar.gz, which is the only evidence left when `dist` is absent.
func distvnameFromPathname(pathname string) string {
	base := path.Base(pathname)
	if base == "." || base == "/" {
		return ""
	}

	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tgz", ".zip"} {
		base = strings.TrimSuffix(base, ext)
	}

	return base
}
