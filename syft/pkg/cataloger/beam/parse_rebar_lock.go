package beam

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseRebarLock

var rebarLockDelimiter = regexp.MustCompile(`[\[{<">},: \]\n]+`)

// parseMixLock parses a mix.lock and returns the discovered Elixir packages.
func parseRebarLock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)

	pkgMap := make(map[string]*pkg.Package)

	var packages []*pkg.Package
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err):
			return packages, nil, nil
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse mix.lock file: %w", err)
		}
		tokens := rebarLockDelimiter.Split(line, -1)
		if len(tokens) < 4 {
			continue
		}
		if len(tokens) < 5 {
			name, hash := tokens[1], tokens[2]
			sourcePkg := pkgMap[name]
			metadata := sourcePkg.Metadata.(pkg.HexMetadata)
			if metadata.PkgHash == "" {
				metadata.PkgHash = hash
			} else {
				metadata.PkgHashExt = hash
			}
			sourcePkg.Metadata = metadata
			continue
		}
		name, version := tokens[1], tokens[4]

		sourcePkg := pkg.Package{
			Name:         name,
			Version:      version,
			Language:     pkg.Beam,
			Type:         pkg.HexPkg,
			MetadataType: pkg.BeamHexMetadataType,
			Metadata: pkg.HexMetadata{
				Name:       name,
				Version:    version,
				PkgHash:    "",
				PkgHashExt: "",
			},
		}

		packages = append(packages, &sourcePkg)
		pkgMap[sourcePkg.Name] = &sourcePkg
	}
}
