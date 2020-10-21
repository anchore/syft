package javascript

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parsePackageLock

// PackageJSON represents a JavaScript package.json file
type PackageJSON struct {
	Version      string            `json:"version"`
	Latest       []string          `json:"latest"`
	Author       string            `json:"author"`
	License      string            `json:"license"`
	Name         string            `json:"name"`
	Homepage     string            `json:"homepage"`
	Description  string            `json:"description"`
	Dependencies map[string]string `json:"dependencies"`
}

// parsePackageJson parses a package.json and returns the discovered JavaScript packages.
func parsePackageJSON(_ string, reader io.Reader) ([]pkg.Package, error) {
	packages := make([]pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var p PackageJSON
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to parse package.json file: %w", err)
		}

		packages = append(packages, pkg.Package{
			Name:         p.Name,
			Version:      p.Version,
			Licenses:     []string{p.License},
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageJsonMetadataType,
			Metadata: pkg.NpmPackageJsonMetadata{
				Author:   p.Author,
				Homepage: p.Homepage,
			},
		})
	}

	return packages, nil
}
