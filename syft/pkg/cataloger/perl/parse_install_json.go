package perl

import (
	"context"
	"encoding/json"
	"path"
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

	name := distributionName(doc)
	if name == "" || doc.Version == "" {
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

	return []pkg.Package{newCpanPackage(name, string(doc.Version), md.Author, md, licenses, locations...)}, nil, nil
}

// distributionName resolves the distribution name, which every consumer of these packages is keyed by.
// The `name` field cannot be used: it holds the module name, so libwww-perl would be reported as LWP
// and CGI-Session as CGI::Session, which no advisory or index is filed against.
//
// `dist` carries the distribution with its version appended, and the version is known, so trimming the
// suffix is exact. That also resolves the case that looks ambiguous when splitting on the last dash:
// CPAN-02Packages-Search-v1.0.0 minus v1.0.0 leaves CPAN-02Packages-Search, where a dash rule would
// have to guess whether v1.0.0 is one segment or three.
func distributionName(doc installJSON) string {
	if doc.Dist != "" {
		if name := strings.TrimSuffix(doc.Dist, "-"+string(doc.Version)); name != "" && name != doc.Dist {
			return name
		}
		// no version suffix to trim, so dist is already the bare name. cpm was checked and does append
		// the version just as cpanm does (see TestInstallJSON_cpmFormatting), so this is a guard against
		// records neither installer is known to write rather than a shape any of them produce.
		return doc.Dist
	}

	// older cpanm and hand-rolled records omit dist; the PAUSE path basename carries the same
	// <Dist>-<Version>.tar.gz shape
	return distributionFromPathname(doc.Pathname, string(doc.Version))
}

// distributionFromPathname recovers the distribution from a PAUSE path such as
// G/GA/GAAS/libwww-perl-5.836.tar.gz, which is the only evidence left when `dist` is absent.
func distributionFromPathname(pathname, version string) string {
	base := path.Base(pathname)
	if base == "." || base == "/" {
		return ""
	}

	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tgz", ".zip"} {
		base = strings.TrimSuffix(base, ext)
	}

	return strings.TrimSuffix(base, "-"+version)
}
