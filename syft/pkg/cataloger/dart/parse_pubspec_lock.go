package dart

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parsePubspecLock

const defaultPubRegistry string = "https://pub.dartlang.org"

type pubspecLock struct {
	Packages map[string]pubspecLockPackage `yaml:"packages"`
	Sdks     map[string]string             `yaml:"sdks"`
}

type pubspecLockPackage struct {
	Dependency  string                 `yaml:"dependency" mapstructure:"dependency"`
	Description pubspecLockDescription `yaml:"description" mapstructure:"description"`
	Source      string                 `yaml:"source" mapstructure:"source"`
	Version     string                 `yaml:"version" mapstructure:"version"`
}

type pubspecLockDescription struct {
	Name        string `yaml:"name" mapstructure:"name"`
	URL         string `yaml:"url" mapstructure:"url"`
	Path        string `yaml:"path" mapstructure:"path"`
	Ref         string `yaml:"ref" mapstructure:"ref"`
	ResolvedRef string `yaml:"resolved-ref" mapstructure:"resolved-ref"`
}

func (p *pubspecLockDescription) UnmarshalYAML(value *yaml.Node) error {
	type pld pubspecLockDescription
	var p2 pld

	if value.Decode(&p.Name) == nil {
		return nil
	}

	if err := value.Decode(&p2); err != nil {
		return err
	}

	*p = pubspecLockDescription(p2)

	return nil
}

func parsePubspecLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	dec := yaml.NewDecoder(reader)

	var p pubspecLock
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pubspec.lock file: %w", err)
	}

	var names []string
	for name, pkg := range p.Packages {
		if pkg.Source == "sdk" && pkg.Version == "0.0.0" {
			// Packages that are delivered as part of an SDK (e.g. Flutter) have their
			// version set to "0.0.0" in the package definition. The actual version
			// should refer to the SDK version, which is defined in a dedicated section
			// in the pubspec.lock file and uses a version range constraint.
			//
			// If such a package is detected, look up the version range constraint of
			// its matching SDK, and set the minimum supported version as its new version.
			sdkName := pkg.Description.Name
			sdkVersion, err := p.getSdkVersion(sdkName)

			if err != nil {
				log.Tracef("failed to resolve %s SDK version for package %s: %v", sdkName, name, err)
				continue
			}
			pkg.Version = sdkVersion
			p.Packages[name] = pkg
		}

		names = append(names, name)
	}

	// always ensure there is a stable ordering of packages
	sort.Strings(names)

	for _, name := range names {
		pubPkg := p.Packages[name]
		pkgs = append(pkgs,
			newPubspecLockPackage(
				name,
				pubPkg,
				reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

// Look up the version range constraint for a given sdk name, if found,
// and return its lowest supported version matching that constraint.
//
// The sdks and their constraints are defined in the pubspec.lock file, e.g.
//
//	sdks:
//		dart: ">=2.12.0 <3.0.0"
//		flutter: ">=3.24.5"
//
// and stored in the pubspecLock.Sdks map during parsing.
//
// Example based on the data above:
//
//	getSdkVersion("dart") -> "2.12.0"
//	getSdkVersion("flutter") -> "3.24.5"
//	getSdkVersion("undefined") -> error
func (psl *pubspecLock) getSdkVersion(sdk string) (string, error) {
	constraint, found := psl.Sdks[sdk]

	if !found {
		return "", fmt.Errorf("cannot find %s SDK", sdk)
	}

	return parseMinimumSdkVersion(constraint)
}

// semverRegex is a regex pattern that allows for both two-part (major.minor) and three-part (major.minor.patch) versions.
// additionally allows for:
//  1. start with either "^" or ">=" (Dart SDK constraints only use those two)
//  2. followed by a valid semantic version (which may be two or three components)
//  3. followed by a space (if there's a range) or end of string
var semverRegex = regexp.MustCompile(`^(\^|>=)(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?(?:-[0-9A-Za-z\-\.]+)?(?:\+[0-9A-Za-z\-\.]+)?)( |$)`)

// Parse a given version range constraint and return its lowest supported version.
//
// This is intended for packages that are part of an SDK (e.g. Flutter) and don't
// have an explicit version string set. This will take the given constraint
// parameter, ensure it's a valid constraint string, and return the lowest version
// within that constraint range.
//
// Examples:
//
//	parseMinimumSdkVersion("^1.2.3") -> "1.2.3"
//	parseMinimumSdkVersion(">=1.2.3") -> "1.2.3"
//	parseMinimumSdkVersion(">=1.2.3 <2.0.0") -> "1.2.3"
//	parseMinimumSdkVersion("1.2.3") -> error
//
// see https://dart.dev/tools/pub/dependencies#version-constraints for the
// constraint format used in Dart SDK defintions.
func parseMinimumSdkVersion(constraint string) (string, error) {
	if !semverRegex.MatchString(constraint) {
		return "", fmt.Errorf("unsupported or invalid constraint '%s'", constraint)
	}

	// Read "version" subexpression into version variable
	var version []byte
	matchIndex := semverRegex.FindStringSubmatchIndex(constraint)
	version = semverRegex.ExpandString(version, "$version", constraint, matchIndex)

	return string(version), nil
}

func (p *pubspecLockPackage) getVcsURL() string {
	if p.Source == "git" {
		if p.Description.Path == "." {
			return fmt.Sprintf("%s@%s", p.Description.URL, p.Description.ResolvedRef)
		}

		return fmt.Sprintf("%s@%s#%s", p.Description.URL, p.Description.ResolvedRef, p.Description.Path)
	}

	return ""
}

func (p *pubspecLockPackage) getHostedURL() string {
	if p.Source == "hosted" && p.Description.URL != defaultPubRegistry {
		u, err := url.Parse(p.Description.URL)
		if err != nil {
			log.Debugf("Unable to parse registry url %w", err)
			return p.Description.URL
		}
		return u.Host
	}

	return ""
}
