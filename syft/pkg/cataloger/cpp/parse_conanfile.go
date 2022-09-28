package cpp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseConanfile

type Conanfile struct {
	Requires []string `toml:"requires"`
}

// parseConanfile is a parser function for conanfile.txt contents, returning all packages discovered.
func parseConanfile(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)
	inRequirements := false
	pkgs := []*pkg.Package{}
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err):
			return pkgs, nil, nil
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse conanfile.txt file: %w", err)
		}

		switch {
		case strings.Contains(line, "[requires]"):
			inRequirements = true
		case strings.ContainsAny(line, "[]#"):
			inRequirements = false
		}

		m := pkg.ConanMetadata{
			Ref: strings.Trim(line, "\n"),
		}

		pkgName, pkgVersion := m.NameAndVersion()

		if pkgName == "" || pkgVersion == "" || !inRequirements {
			continue
		}

		pkgs = append(pkgs, &pkg.Package{
			Name:         pkgName,
			Version:      pkgVersion,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata:     m,
		})
	}
}
