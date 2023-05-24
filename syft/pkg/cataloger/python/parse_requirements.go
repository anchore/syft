package python

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseRequirementsTxt

var (
	extrasRegex = regexp.MustCompile(`\[.*\]`)
	urlRegex    = regexp.MustCompile("@.*git.*")
)

// parseRequirementsTxt takes a Python requirements.txt file, returning all Python packages that are locked to a
// specific version.
func parseRequirementsTxt(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		rawLineNoComments := removeTrailingComment(line)
		line = trimRequirementsTxtLine(line)

		if line == "" {
			// nothing to parse on this line
			continue
		}

		if strings.HasPrefix(line, "-e") {
			// editable packages aren't parsed (yet)
			continue
		}

		if !strings.Contains(line, "==") {
			// a package without a version, or a range (unpinned) which does not tell us
			// exactly what will be installed.
			continue
		}

		// parse a new requirement
		parts := strings.Split(line, "==")
		if len(parts) < 2 {
			// this should never happen, but just in case
			log.WithFields("path", reader.RealPath).Warnf("unable to parse requirements.txt line: %q", line)
			continue
		}

		// check if the version contains hash declarations on the same line
		version, _ := parseVersionAndHashes(parts[1])

		name := strings.TrimSpace(parts[0])
		version = strings.TrimFunc(version, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)
		})

		// TODO: Update to support more than only ==
		versionConstraint := fmt.Sprintf("== %s", version)

		if name == "" || version == "" {
			log.WithFields("path", reader.RealPath).Debugf("found empty package in requirements.txt line: %q", line)
			continue
		}
		packages = append(
			packages,
			newPackageForRequirementsWithMetadata(
				name,
				version,
				pkg.PythonRequirementsMetadata{
					Name:              name,
					Extras:            parseExtras(rawLineNoComments),
					VersionConstraint: versionConstraint,
					URL:               parseURL(rawLineNoComments),
					Markers:           parseMarkers(rawLineNoComments),
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
	line = checkForRegex(line) // remove extras and url from line if found

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

func parseExtras(packageName string) []string {
	if extrasRegex.MatchString(packageName) {
		// Remove square brackets
		extras := strings.TrimFunc(extrasRegex.FindString(packageName), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)
		})

		// Remove any additional whitespace
		extras = strings.ReplaceAll(extras, " ", "")

		return strings.Split(extras, ",")
	}

	return []string{}
}

func parseMarkers(line string) map[string]string {
	markers := map[string]string{}
	parts := strings.SplitN(line, ";", 2)

	if len(parts) == 2 {
		splittableMarkers := parts[1]

		for _, combineString := range []string{" or ", " and "} {
			splittableMarkers = strings.TrimSpace(
				strings.ReplaceAll(splittableMarkers, combineString, ","),
			)
		}

		splittableMarkers = strings.TrimSpace(splittableMarkers)

		for _, mark := range strings.Split(splittableMarkers, ",") {
			markparts := strings.Split(mark, " ")
			markers[markparts[0]] = strings.Join(markparts[1:], " ")
		}
	}

	return markers
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

// function to check a string for all possilbe regex expressions, replacing it if found
func checkForRegex(stringToCheck string) string {
	stringToReturn := stringToCheck

	for _, r := range []*regexp.Regexp{
		urlRegex,
		extrasRegex,
	} {
		if r.MatchString(stringToCheck) {
			stringToReturn = r.ReplaceAllString(stringToCheck, "")
		}
	}

	return stringToReturn
}
