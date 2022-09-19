package haskell

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
var _ common.ParserFn = parseCabalFreeze

// parseCabalFreeze is a parser function for cabal.project.freeze contents, returning all packages discovered.
func parseCabalFreeze(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)
	pkgs := []*pkg.Package{}
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err):
			return pkgs, nil, nil
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse cabal.project.freeze file: %w", err)
		}

		if !strings.Contains(line, "any.") {
			continue
		}

		line = strings.TrimSpace(line)
		startPkgEncoding, endPkgEncoding := strings.Index(line, "any.")+4, strings.Index(line, ",")
		line = line[startPkgEncoding:endPkgEncoding]
		splits := strings.Split(line, " ==")

		pkgName, pkgVersion := splits[0], splits[1]
		pkgs = append(pkgs, &pkg.Package{
			Name:         pkgName,
			Version:      pkgVersion,
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    pkgName,
				Version: pkgVersion,
			},
		})
	}
}
