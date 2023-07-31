package python

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	// given the example requirement:
	//    requests[security] == 2.8.* ; python_version < "2.7" and sys_platform == "linux"  \
	//      --hash=sha256:a9b3aaa1904eeb78e32394cd46c6f37ac0fb4af6dc488daa58971bdc7d7fcaf3 \
	//      --hash=sha256:e9535b8c84dc9571a48999094fda7f33e63c3f1b74f3e5f3ac0105a58405bb65  # some comment

	// namePattern matches: requests[security]
	namePattern = `(?P<name>\w[\w\[\],\s-_]+)`

	// versionConstraintPattern matches: == 2.8.*
	versionConstraintPattern = `(?P<versionConstraint>([^\S\r\n]*[~=>!<]+\s*[0-9a-zA-Z.*]+[^\S\r\n]*,?)+)?(@[^\S\r\n]*(?P<url>[^;]*))?`

	// markersPattern matches: python_version < "2.7" and sys_platform == "linux"
	markersPattern = `(;(?P<markers>.*))?`

	// hashesPattern matches: --hash=sha256:a9b3aaa1904eeb78e32394cd46c6f37ac0fb4af6dc488daa58971bdc7d7fcaf3 --hash=sha256:e9535b8c84dc9571a48999094fda7f33e63c3f1b74f3e5f3ac0105a58405bb65
	hashesPattern = `(?P<hashes>([^\S\r\n]*--hash=[a-zA-Z0-9:]+)+)?`

	// whiteSpaceNoNewlinePattern matches: (any whitespace character except for \r and \n)
	whiteSpaceNoNewlinePattern = `[^\S\r\n]*`
)

var requirementPattern = regexp.MustCompile(
	`^` +
		whiteSpaceNoNewlinePattern +
		namePattern +
		whiteSpaceNoNewlinePattern +
		versionConstraintPattern +
		markersPattern +
		hashesPattern,
)

type unprocessedRequirement struct {
	Name              string `mapstructure:"name"`
	VersionConstraint string `mapstructure:"versionConstraint"`
	Markers           string `mapstructure:"markers"`
	URL               string `mapstructure:"url"`
	Hashes            string `mapstructure:"hashes"`
}

func newRequirement(raw string) *unprocessedRequirement {
	var r unprocessedRequirement

	values := internal.MatchNamedCaptureGroups(requirementPattern, raw)

	if err := mapstructure.Decode(values, &r); err != nil {
		return nil
	}

	r.Name = strings.TrimSpace(r.Name)
	r.VersionConstraint = strings.TrimSpace(r.VersionConstraint)
	r.Markers = strings.TrimSpace(r.Markers)
	r.URL = strings.TrimSpace(r.URL)
	r.Hashes = strings.TrimSpace(r.Hashes)

	if r.Name == "" {
		return nil
	}

	return &r
}

type requirementsParser struct {
	guessUnpinnedRequirements bool
}

func newRequirementsParser(cfg CatalogerConfig) requirementsParser {
	return requirementsParser{
		guessUnpinnedRequirements: cfg.GuessUnpinnedRequirements,
	}
}

// parseRequirementsTxt takes a Python requirements.txt file, returning all Python packages that are locked to a
// specific version.
func (rp requirementsParser) parseRequirementsTxt(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package

	scanner := bufio.NewScanner(reader)
	var lastLine string
	for scanner.Scan() {
		line := trimRequirementsTxtLine(scanner.Text())

		if lastLine != "" {
			line = lastLine + line
			lastLine = ""
		}

		// remove line continuations... smashes the file into a single line
		if strings.HasSuffix(line, "\\") {
			// this line is a continuation of the previous line
			lastLine += strings.TrimSuffix(line, "\\")
			continue
		}

		if line == "" {
			// nothing to parse on this line
			continue
		}

		if strings.HasPrefix(line, "-e") {
			// editable packages aren't parsed (yet)
			continue
		}

		req := newRequirement(line)
		if req == nil {
			log.WithFields("path", reader.RealPath).Warnf("unable to parse requirements.txt line: %q", line)
			continue
		}

		name := removeExtras(req.Name)
		version := parseVersion(req.VersionConstraint, rp.guessUnpinnedRequirements)

		if version == "" {
			log.WithFields("path", reader.RealPath).Tracef("unable to determine package version in requirements.txt line: %q", line)
			continue
		}

		packages = append(
			packages,
			newPackageForRequirementsWithMetadata(
				name,
				version,
				pkg.PythonRequirementsMetadata{
					Name:              name,
					Extras:            parseExtras(req.Name),
					VersionConstraint: req.VersionConstraint,
					URL:               parseURL(req.URL),
					Markers:           req.Markers,
				},
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse python requirements file: %w", err)
	}

	return packages, nil, nil
}

func parseVersion(version string, guessFromConstraint bool) string {
	if isPinnedConstraint(version) {
		return strings.TrimSpace(strings.ReplaceAll(version, "==", ""))
	}

	if guessFromConstraint {
		return guessVersion(version)
	}

	return ""
}

func isPinnedConstraint(version string) bool {
	return strings.Contains(version, "==") && !strings.ContainsAny(version, "*,<>!")
}

func guessVersion(constraint string) string {
	// handle "2.8.*" -> "2.8.0"
	constraint = strings.ReplaceAll(constraint, "*", "0")
	if isPinnedConstraint(constraint) {
		return strings.TrimSpace(strings.ReplaceAll(constraint, "==", ""))
	}

	constraints := strings.Split(constraint, ",")
	filteredVersions := map[string]struct{}{}
	for _, part := range constraints {
		if strings.Contains(part, "!=") {
			parts := strings.Split(part, "!=")
			filteredVersions[strings.TrimSpace(parts[1])] = struct{}{}
		}
	}

	var closestVersion *pep440.Version
	for _, part := range constraints {
		// ignore any parts that do not have '=' in them, >,<,~ are not valid semver
		parts := strings.SplitAfter(part, "=")
		if len(parts) < 2 {
			continue
		}
		version, err := pep440.Parse(strings.TrimSpace(parts[1]))
		if err != nil {
			// ignore any parts that are not valid semver
			continue
		}
		if _, ok := filteredVersions[version.String()]; ok {
			continue
		}

		if strings.Contains(part, "==") {
			parts := strings.Split(part, "==")
			return strings.TrimSpace(parts[1])
		}

		if closestVersion == nil || version.GreaterThan(*closestVersion) {
			closestVersion = &version
		}
	}
	if closestVersion == nil {
		return ""
	}

	return closestVersion.String()
}

// trimRequirementsTxtLine removes content from the given requirements.txt line
// that should not be considered for parsing.
func trimRequirementsTxtLine(line string) string {
	line = strings.TrimSpace(line)
	line = removeTrailingComment(line)

	return line
}

// removeTrailingComment takes a requirements.txt line and strips off comment strings.
func removeTrailingComment(line string) string {
	parts := strings.SplitN(line, "#", 2)
	if len(parts) < 2 {
		// there aren't any comments

		return line
	}

	return parts[0]
}

func removeExtras(packageName string) string {
	start := strings.Index(packageName, "[")
	if start == -1 {
		return packageName
	}

	return strings.TrimSpace(packageName[:start])
}

func parseExtras(packageName string) []string {
	var extras []string

	start := strings.Index(packageName, "[")
	stop := strings.Index(packageName, "]")
	if start == -1 || stop == -1 {
		return extras
	}

	extraString := packageName[start+1 : stop]
	for _, extra := range strings.Split(extraString, ",") {
		extras = append(extras, strings.TrimSpace(extra))
	}
	return extras
}

func parseURL(line string) string {
	parts := strings.Split(line, "@")

	if len(parts) > 1 {
		desiredIndex := -1

		for index, part := range parts {
			part := strings.TrimFunc(part, func(r rune) bool {
				return !unicode.IsLetter(r) && !unicode.IsNumber(r)
			})

			if strings.HasPrefix(part, "git") {
				desiredIndex = index
				break
			}
		}

		if desiredIndex != -1 {
			return strings.TrimSpace(strings.Join(parts[desiredIndex:], "@"))
		}
	}

	return ""
}
