package perl

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// versionPattern matches the $VERSION assignment perl modules declare, e.g. `our $VERSION = '2.06';`.
// The value is captured as written so that both decimal (1.303) and v-string (v1.1.4) forms survive intact.
//
// Requiring a literal after the `=` is what makes the pattern decline the computed forms, which cannot be
// read statically at all: real Encode.pm is a bare `our $VERSION;` followed by
// `$VERSION = sprintf "%d.%02d", q$Revision: 3.24 $ =~ /(\d+)/g;` inside a BEGIN block. Those come from
// perllocal.pod instead, which records what the installer evaluated.
//
// The optional package prefix covers the fully qualified form older Dist::Zilla wrote,
// `$JSON::PP::VERSION = '2.27300';`, and qv() covers `our $VERSION = qv('1.2.3');`.
var versionPattern = regexp.MustCompile(`^[ \t]*(?:our[ \t]+|my[ \t]+)?\$(?:[A-Za-z_][A-Za-z0-9_]*::)*VERSION[ \t]*=[ \t]*(?:qv\()?['"]?(v?[0-9][0-9._]*)`)

// packageVersionPattern matches a version declared in the package statement itself,
// `package CPAN::02Packages::Search v1.0.0;`, which perl 5.12 and later allow. A distribution using it
// need carry no $VERSION assignment anywhere: real CPAN::02Packages::Search v1.0.0 does not.
var packageVersionPattern = regexp.MustCompile(`^[ \t]*package[ \t]+[A-Za-z_][A-Za-z0-9_:]*[ \t]+(v?[0-9][0-9._]*)[ \t]*[;{]`)

// packlistMetadataSuffix matches the trailing `key=value` metadata that ExtUtils::Packlist::read strips
// from a packlist line, following the `/^(.*?)( \w+=.*)$/` it uses. Cutting at the first space instead
// truncates any real path that contains one, which corrupts both the owned-file list and the main-.pm
// version fallback.
var packlistMetadataSuffix = regexp.MustCompile(` \w+=.*$`)

// parsePacklist catalogs a distribution installed by any ExtUtils::MakeMaker or Module::Build run,
// which covers CPAN.pm (which writes no .meta) and the perl image's own preinstalled distributions.
func parsePacklist(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	name := distNameFromPacklistPath(reader.Path())
	if name == "" {
		// the perl core packlist has no auto/<Dist> segment; it lists thousands of files and describes
		// no single distribution
		return nil, nil, nil
	}

	var files []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// packlist lines are "<path>" or "<path> type=link from=<path>"
		if f := strings.TrimSpace(packlistMetadataSuffix.ReplaceAllString(scanner.Text(), "")); f != "" {
			files = append(files, f)
		}
	}

	location := reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)
	md := pkg.CpanDistribution{MainModule: moduleFromDashedName(name), Files: files}

	// the version is left to resolvePacklistVersions, which prefers perllocal.pod and needs the whole
	// cataloged set to find it. A distribution with no readable version is still reported, so that it
	// stays visible.
	return []pkg.Package{newCpanPackage(name, "", "", md, nil, location)}, nil, nil
}

// distNameFromPacklistPath derives the distribution name from the packlist path, e.g.
// .../auto/IO/Socket/SSL/.packlist yields IO-Socket-SSL. A path with no auto/ segment yields "".
func distNameFromPacklistPath(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")

	last := -1
	for i, part := range parts {
		if part == "auto" {
			last = i
		}
	}

	if last < 0 || last+1 >= len(parts)-1 {
		return ""
	}

	return strings.Join(parts[last+1:len(parts)-1], "-")
}

// mainModuleFile picks the .pm file in the packlist that corresponds to the distribution's main module,
// e.g. Text-CSV is expected to install Text/CSV.pm.
//
// The suffix can match more than one entry, and taking the first is wrong: libwww-perl's packlist lists
// both Bundle/LWP.pm (5.835) and LWP.pm (5.836), with the Bundle copy first. The main module sits at the
// lib root, so the shallowest match is the right one; a nested match is some other module that merely
// ends in the same basename.
func mainModuleFile(dist string, files []string) string {
	suffix := "/" + strings.ReplaceAll(dist, "-", "/") + ".pm"

	best := ""
	bestDepth := 0
	for _, f := range files {
		if !strings.HasSuffix(f, suffix) {
			continue
		}
		if depth := strings.Count(f, "/"); best == "" || depth < bestDepth {
			best, bestDepth = f, depth
		}
	}

	return best
}

func findFile(resolver file.Resolver, p string) (file.Location, bool) {
	if resolver == nil || p == "" {
		return file.Location{}, false
	}
	locations, err := resolver.FilesByPath(p)
	if err != nil || len(locations) == 0 {
		return file.Location{}, false
	}
	return locations[0], true
}

func readVersionFromPM(resolver file.Resolver, location file.Location) string {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return ""
	}
	defer internal.CloseAndLogError(reader, location.Path())

	return versionFromPM(reader)
}

func versionFromPM(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range []*regexp.Regexp{versionPattern, packageVersionPattern} {
			if match := pattern.FindStringSubmatch(line); match != nil {
				return strings.TrimRight(match[1], ".")
			}
		}
	}
	return ""
}
