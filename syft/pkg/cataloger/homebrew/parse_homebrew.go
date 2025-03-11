package homebrew

import (
	"bufio"
	"context"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type parsedHomebrewData struct {
	Name     string
	Version  string
	Desc     string
	Homepage string
}

func parseHomebrewPackage(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	pathParts := strings.Split(reader.Location.RealPath, string(filepath.Separator))
	var pkgName, pkgVersion string
	for i, part := range pathParts {
		if part == "Cellar" && i+2 < len(pathParts) {
			pkgName = pathParts[i+1]
			pkgVersion = pathParts[i+2]
			break
		}
	}

	if pkgName == "" || pkgVersion == "" {
		return nil, nil, nil
	}

	pd, err := parseFormulaFile(reader)
	if err != nil {
		log.WithFields("package", pkgName).Warn("failed to parse formula")
		return nil, nil, err
	}

	locations := file.NewLocationSet()

	locations.Add(reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	cellarPath := filepath.Dir(filepath.Dir(reader.Location.RealPath))
	locations.Add(file.NewLocation(cellarPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))

	if resolver != nil {
		if matches, err := resolver.FilesByGlob(filepath.Join("/usr/local/bin", pkgName)); err == nil && len(matches) > 0 {
			locations.Add(matches[0].WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
		}
		if matches, err := resolver.FilesByGlob(filepath.Join("/opt/homebrew/bin", pkgName)); err == nil && len(matches) > 0 {
			locations.Add(matches[0].WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
		}
	}

	p := newHomebrewPackage(
		pkgName,
		pkgVersion,
		pd.Desc,
		pd.Homepage,
		locations)

	pkgs = append(pkgs, p)

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to discover Homebrew package")
}

func parseFormulaFile(reader file.LocationReadCloser) (*parsedHomebrewData, error) {
	pd := &parsedHomebrewData{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "desc ") {
			pd.Desc = extractQuotedValue(line[5:])
		} else if strings.HasPrefix(line, "homepage ") {
			pd.Homepage = extractQuotedValue(line[9:])
		}

		if pd.Desc != "" && pd.Homepage != "" {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pd, nil
}

func extractQuotedValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		return s[1 : len(s)-1]
	}

	return s
}
