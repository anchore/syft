package cpp

import (
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/pelletier/go-toml"
)

// integrity check
var _ common.ParserFn = parseConanfile

type Conanfile struct {
	Requires []string `toml:"requires"`
}

// parseConanfile is a parser function for conanfile.txt contents, returning all packages discovered.
func parseConanfile(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load conanfile.txt for parsing: %w", err)
	}

	conanfile := Conanfile{}
	err = tree.Unmarshal(&conanfile)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse conanfile.txt: %w", err)
	}

	pkgs := []*pkg.Package{}
	for _, requiredPackage := range conanfile.Requires {
		splits := strings.Split(strings.TrimSpace(requiredPackage), "/")
		pkgName, pkgVersion := splits[0], splits[1]
		pkgs = append(pkgs, &pkg.Package{
			Name:         pkgName,
			Version:      pkgVersion,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata: pkg.ConanMetadata{
				Name:    pkgName,
				Version: pkgVersion,
			},
		})
	}
	return pkgs, nil, nil
}
