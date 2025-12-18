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

type setupFileParser struct {
	cfg             CatalogerConfig
	licenseResolver pythonLicenseResolver
}

func newSetupFileParser(cfg CatalogerConfig) setupFileParser {
	return setupFileParser{
		cfg:             cfg,
		licenseResolver: newPythonLicenseResolver(cfg),
	}
}

// match examples:
//
//	'pathlib3==2.2.0;python_version<"3.6"'  --> match(name=pathlib3 version=2.2.0)
//	 "mypy==v0.770",                        --> match(name=mypy version=v0.770)
//	" mypy2 == v0.770", ' mypy3== v0.770',  --> match(name=mypy2 version=v0.770), match(name=mypy3, version=v0.770)
var pinnedDependency = regexp.MustCompile(`['"]\W?(\w+\W?==\W?[\w.]*)`)
var unquotedPinnedDependency = regexp.MustCompile(`^\s*(\w+)\s*==\s*([\w\.\-]+)`)

func (sp setupFileParser) parseSetupFile(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\n")

		packages = sp.processQuotedDependencies(ctx, line, reader, packages)
		packages = sp.processUnquotedDependency(ctx, line, reader, packages)
	}

	return packages, nil, nil
}

func (sp setupFileParser) processQuotedDependencies(ctx context.Context, line string, reader file.LocationReadCloser, packages []pkg.Package) []pkg.Package {
	for _, match := range pinnedDependency.FindAllString(line, -1) {
		if p, ok := sp.parseQuotedDependency(ctx, match, line, reader); ok {
			packages = append(packages, p)
		}
	}
	return packages
}

func (sp setupFileParser) parseQuotedDependency(ctx context.Context, match, line string, reader file.LocationReadCloser) (pkg.Package, bool) {
	parts := strings.Split(match, "==")
	if len(parts) != 2 {
		return pkg.Package{}, false
	}

	name := cleanDependencyString(parts[0])
	version := cleanDependencyString(parts[len(parts)-1])

	return sp.validateAndCreatePackage(ctx, name, version, line, reader)
}

// processUnquotedDependency extracts and processes an unquoted dependency from a line
func (sp setupFileParser) processUnquotedDependency(ctx context.Context, line string, reader file.LocationReadCloser, packages []pkg.Package) []pkg.Package {
	matches := unquotedPinnedDependency.FindStringSubmatch(line)
	if len(matches) != 3 {
		return packages
	}

	name := strings.TrimSpace(matches[1])
	version := strings.TrimSpace(matches[2])

	if p, ok := sp.validateAndCreatePackage(ctx, name, version, line, reader); ok {
		if !isDuplicatePackage(p, packages) {
			packages = append(packages, p)
		}
	}

	return packages
}

func cleanDependencyString(s string) string {
	s = strings.Trim(s, "'\"")
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "'\"")
	return s
}

func (sp setupFileParser) validateAndCreatePackage(ctx context.Context, name, version, line string, reader file.LocationReadCloser) (pkg.Package, bool) {
	if hasTemplateDirective(name) || hasTemplateDirective(version) {
		// this can happen in more dynamic setup.py where there is templating
		return pkg.Package{}, false
	}

	if name == "" || version == "" {
		log.WithFields("path", reader.RealPath).Debugf("unable to parse package in setup.py line: %q", line)
		return pkg.Package{}, false
	}

	p := newPackageForIndex(
		ctx,
		sp.licenseResolver,
		name,
		version,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	return p, true
}

func isDuplicatePackage(p pkg.Package, packages []pkg.Package) bool {
	for _, existing := range packages {
		if existing.Name == p.Name && existing.Version == p.Version {
			return true
		}
	}
	return false
}

func hasTemplateDirective(s string) bool {
	return strings.Contains(s, `%s`) || strings.Contains(s, `{`) || strings.Contains(s, `}`)
}
