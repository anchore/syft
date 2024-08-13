package python

import (
	"bufio"
	"context"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parseSetup

// match examples:
//
//	'pathlib3==2.2.0;python_version<"3.6"'  --> match(name=pathlib3 version=2.2.0)
//	 "mypy==v0.770",                        --> match(name=mypy version=v0.770)
//	" mypy2 == v0.770", ' mypy3== v0.770',  --> match(name=mypy2 version=v0.770), match(name=mypy3, version=v0.770)
var pinnedDependency = regexp.MustCompile(`['"]\W?(\w+\W?==\W?[\w.]*)`)

func parseSetup(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\n")

		for _, match := range pinnedDependency.FindAllString(line, -1) {
			parts := strings.Split(match, "==")
			if len(parts) != 2 {
				continue
			}
			name := strings.Trim(parts[0], "'\"")
			name = strings.TrimSpace(name)
			name = strings.Trim(name, "'\"")

			version := strings.TrimSpace(parts[len(parts)-1])
			version = strings.Trim(version, "'\"")

			if hasTemplateDirective(name) || hasTemplateDirective(version) {
				// this can happen in more dynamic setup.py where there is templating
				continue
			}

			if name == "" || version == "" {
				log.WithFields("path", reader.RealPath).Debugf("unable to parse package in setup.py line: %q", line)
				continue
			}

			packages = append(
				packages,
				newPackageForIndex(
					name,
					version,
					reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				),
			)
		}
	}

	return packages, nil, nil
}

func hasTemplateDirective(s string) bool {
	return strings.Contains(s, `%s`) || strings.Contains(s, `{`) || strings.Contains(s, `}`)
}
