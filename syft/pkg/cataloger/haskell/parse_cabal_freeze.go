package haskell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseCabalFreeze

// parseCabalFreeze is a parser function for cabal.project.freeze contents, returning all packages discovered.
func parseCabalFreeze(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)
	var pkgs []pkg.Package
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(err, io.EOF):
			return pkgs, nil, nil
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse cabal.project.freeze file: %w", err)
		}

		if !strings.Contains(line, "any.") {
			continue
		}

		line = strings.TrimSpace(line)
		startPkgEncoding, endPkgEncoding := strings.Index(line, "any.")+4, strings.Index(line, ",")
		// case where comma not found for last package in constraint list
		if endPkgEncoding == -1 {
			endPkgEncoding = len(line)
		}
		if startPkgEncoding >= endPkgEncoding || startPkgEncoding < 0 {
			continue
		}

		line = line[startPkgEncoding:endPkgEncoding]
		fields := strings.Split(line, " ==")

		pkgName, pkgVersion := fields[0], fields[1]
		pkgs = append(
			pkgs,
			newPackage(
				pkgName,
				pkgVersion,
				nil,
				reader.Location,
			),
		)
	}
}
