package homebrew

import (
	"bufio"
	"context"
	"path"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type parsedHomebrewData struct {
	Tap      string
	Name     string
	Version  string
	Desc     string
	Homepage string
	License  string
}

func parseHomebrewFormula(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pd, err := parseFormulaFile(reader)
	if err != nil {
		log.WithFields("path", reader.RealPath).Trace("failed to parse formula")
		return nil, nil, err
	}

	if pd == nil {
		return nil, nil, nil
	}

	return []pkg.Package{
		newHomebrewPackage(
			*pd,
			reader.Location,
		),
	}, nil, nil
}

func parseFormulaFile(reader file.LocationReadCloser) (*parsedHomebrewData, error) {
	pd := &parsedHomebrewData{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case strings.HasPrefix(line, "desc "):
			pd.Desc = getQuotedValue(line)
		case strings.HasPrefix(line, "homepage "):
			pd.Homepage = getQuotedValue(line)
		case strings.HasPrefix(line, "license "):
			pd.License = getQuotedValue(line)
		case strings.HasPrefix(line, "name "):
			pd.Name = getQuotedValue(line)
		case strings.HasPrefix(line, "version "):
			pd.Version = getQuotedValue(line)
		}
	}

	pd.Tap = getTapFromPath(reader.RealPath)

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if pd.Name != "" && pd.Version != "" {
		return pd, nil
	}

	pathParts := strings.Split(reader.RealPath, "/")
	var pkgName, pkgVersion string
	for i, part := range pathParts {
		if part == "Cellar" && i+2 < len(pathParts) {
			pkgName = pathParts[i+1]
			pkgVersion = pathParts[i+2]
			break
		}
	}

	if pd.Name == "" {
		if pkgName != "" {
			pd.Name = pkgName
		} else if strings.HasSuffix(reader.RealPath, ".rb") {
			// get it from the filename
			// e.g. foo.rb
			pd.Name = strings.TrimSuffix(path.Base(reader.RealPath), ".rb")
		}
	}

	if pd.Version == "" {
		pd.Version = pkgVersion
	}

	return pd, nil
}

func getTapFromPath(path string) string {
	// get testorg/sometap from opt/homebrew/Library/Taps/testorg/sometap/Formula/bar.rb
	// key off of Library/Taps/ as the path just before the org/tap name

	paths := strings.Split(path, "Library/Taps")
	if len(paths) < 2 {
		return ""
	}

	paths = strings.Split(paths[1], "/")
	if len(paths) < 3 {
		return ""
	}
	return strings.Join(paths[1:3], "/")
}

func getQuotedValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	start := strings.Index(s, "\"")
	if start == -1 {
		return ""
	}

	end := strings.LastIndex(s, "\"")
	if end == -1 || end <= start {
		return ""
	}

	return s[start+1 : end]
}
