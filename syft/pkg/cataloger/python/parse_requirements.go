package python

import (
	"bufio"
	"fmt"
	"strings"
	"unicode"

	"github.com/Masterminds/semver/v3"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

var _ generic.Parser = parseRequirementsTxt

// parseRequirementsTxt takes a Python requirements.txt file, returning all Python packages that are locked to a
// specific version.
func parseRequirementsTxt(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		line = trimRequirementsTxtLine(line)

		if line == "" {
			// nothing to parse on this line
			continue
		}

		if strings.HasPrefix(line, "-e") {
			// editable packages aren't parsed (yet)
			continue
		}

		var parts []string
		if strings.Contains(line, "==") {
			parts = strings.Split(line, "==")
		}
		// Using min/max version is better than ignoring the package, however, it does not provide the same level of
		// confidence as a pinned version.
		index := strings.IndexFunc(line, func(r rune) bool {
			return r == '>' || r == '<' || r == '~'
		})

		if index > 0 {
			parts = append(parts, line[:index], line[index:])
		}

		if len(parts) < 2 {
			// this should never happen, but just in case
			log.WithFields("path", reader.RealPath).Warnf("unable to parse requirements.txt line: %q", line)
			continue
		}

		// check if the version contains hash declarations on the same line
		version, _ := parseVersionAndHashes(parts[1])
		version = parseVersion(version)
		name := strings.TrimSpace(parts[0])
		version = strings.TrimFunc(version, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)
		})

		if name == "" || version == "" {
			log.WithFields("path", reader.RealPath).Debugf("found empty package in requirements.txt line: %q", line)
			continue
		}
		packages = append(packages, newPackageForIndex(name, version, reader.Location))
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse python requirements file: %w", err)
	}

	return packages, nil, nil
}

func parseVersion(version string) string {
	parts := strings.Split(version, ",")
	if len(parts) < 2 {
		return version
	}

	closestVersion := semver.MustParse("0.0.0")
	filteredVersions := make(map[string]struct{})
	for _, part := range parts {
		if strings.Contains(part, "!=") {
			parts := strings.Split(part, "!=")
			filteredVersions[parts[1]] = struct{}{}
		}
	}

	for _, part := range parts {
		// ignore any parts that do not have '=' in them, >,<,~ are not valid semver
		parts := strings.SplitAfter(part, "=")
		if len(parts) < 2 {
			continue
		}
		version := semver.MustParse(strings.TrimSpace(parts[1]))
		if _, ok := filteredVersions[version.String()]; ok {
			continue
		}

		if strings.Contains(part, "==") {
			parts := strings.Split(part, "==")
			return parts[1]
		}

		cmp := version.Compare(closestVersion)
		if cmp > 0 {
			closestVersion = version
		} else if cmp < 0 {
			continue
		}
	}

	return closestVersion.String()
}

func parseVersionAndHashes(version string) (string, []string) {
	parts := strings.Split(version, "--hash=")
	if len(parts) < 2 {
		return version, nil
	}

	return parts[0], parts[1:]
}

// trimRequirementsTxtLine removes content from the given requirements.txt line
// that should not be considered for parsing.
func trimRequirementsTxtLine(line string) string {
	line = strings.TrimSpace(line)
	line = removeTrailingComment(line)
	line = removeEnvironmentMarkers(line)

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

// removeEnvironmentMarkers removes any instances of environment markers (delimited by ';') from the line.
// For more information, see https://www.python.org/dev/peps/pep-0508/#environment-markers.
func removeEnvironmentMarkers(line string) string {
	parts := strings.SplitN(line, ";", 2)
	if len(parts) < 2 {
		// there aren't any environment markers

		return line
	}

	return parts[0]
}
