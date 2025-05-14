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
	pd := parsedHomebrewData{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "class ") && strings.Contains(line, " < Formula") {
			// this is the start of the class declaration, ignore anything before this
			pd = parsedHomebrewData{}
			continue
		}

		switch {
		case matchesVariable(line, "desc"):
			pd.Desc = getQuotedValue(line)
		case matchesVariable(line, "homepage"):
			pd.Homepage = getQuotedValue(line)
		case matchesVariable(line, "license"):
			pd.License = getQuotedValue(line)
		case matchesVariable(line, "name"):
			pd.Name = getQuotedValue(line)
		case matchesVariable(line, "version"):
			pd.Version = getQuotedValue(line)
		}
	}

	pd.Tap = getTapFromPath(reader.RealPath)

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if pd.Name != "" && pd.Version != "" {
		return &pd, nil
	}

	pd.Name, pd.Version = getNameAndVersionFromPath(reader.RealPath)

	return &pd, nil
}

func matchesVariable(line, name string) bool {
	// should return true if the line starts with "name<space>" or "name<tab>"
	return strings.HasPrefix(line, name+" ") || strings.HasPrefix(line, name+"\t")
}

func getNameAndVersionFromPath(p string) (string, string) {
	if p == "" {
		return "", ""
	}

	pathParts := strings.Split(p, "/")

	// extract from a formula path...
	// e.g. /opt/homebrew/Cellar/foo/1.0.0/.brew/foo.rb
	var name, ver string
	for i := len(pathParts) - 1; i >= 0; i-- {
		if pathParts[i] == ".brew" && i-2 >= 0 {
			name = pathParts[i-2]
			ver = pathParts[i-1]
			break
		}
	}

	if name == "" {
		// get it from the filename
		name = strings.TrimSuffix(path.Base(p), ".rb")
	}

	return name, ver
}

func getTapFromPath(path string) string {
	// get testorg/sometap from opt/homebrew/Library/Taps/testorg/sometap/Formula/bar.rb
	// key off of Library/Taps/ as the path just before the org/tap name

	paths := strings.Split(path, "Library/Taps/")
	if len(paths) < 2 {
		return ""
	}

	paths = strings.Split(paths[1], "/")
	if len(paths) < 2 {
		return ""
	}
	return strings.Join(paths[0:2], "/")
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
