package dotnet

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseDotnetDeps

type dotnetDeps struct {
	Libraries map[string]dotnetDepsLibrary `json:"libraries"`
}

type dotnetDepsLibrary struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	Sha512   string `json:"sha512"`
	HashPath string `json:"hashPath"`
}

func parseDotnetDeps(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	var packages []*pkg.Package

	dec := json.NewDecoder(reader)

	var p dotnetDeps
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("failed to parse deps.json file: %w", err)
	}

	for nameVersion, lib := range p.Libraries {
		dotnetPkg := newDotnetDepsPackage(nameVersion, lib)

		if dotnetPkg != nil {
			packages = append(packages, dotnetPkg)
		}
	}

	return packages, nil, nil
}

func newDotnetDepsPackage(nameVersion string, lib dotnetDepsLibrary) *pkg.Package {
	if lib.Type != "package" {
		return nil
	}

	splitted := strings.Split(nameVersion, "/")
	name := splitted[0]
	version := splitted[1]

	return &pkg.Package{
		Name:         name,
		Version:      version,
		Language:     pkg.Dotnet,
		Type:         pkg.DotnetPkg,
		MetadataType: pkg.DotnetDepsMetadataType,
		Metadata: &pkg.DotnetDepsMetadata{
			Name:     name,
			Version:  version,
			Path:     lib.Path,
			Sha512:   lib.Sha512,
			HashPath: lib.HashPath,
		},
	}
}
