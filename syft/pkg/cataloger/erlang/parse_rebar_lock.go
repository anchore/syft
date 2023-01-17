package erlang

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

// integrity check
var _ generic.Parser = parseRebarLock

var rebarLockDelimiter = regexp.MustCompile(`[\[{<">},: \]\n]+`)

// parseMixLock parses a mix.lock and returns the discovered Elixir packages.
func parseRebarLock(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)

	pkgMap := make(map[string]*pkg.Package)

	var names []string
loop:
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err):
			break loop
		case err != nil:
			// TODO: return partial result and warn
			return nil, nil, fmt.Errorf("failed to parse rebar.lock file: %w", err)
		}
		tokens := rebarLockDelimiter.Split(line, -1)
		if len(tokens) < 4 {
			continue
		}
		if len(tokens) < 5 {
			name, hash := tokens[1], tokens[2]
			sourcePkg := pkgMap[name]
			metadata, ok := sourcePkg.Metadata.(pkg.RebarLockMetadata)
			if !ok {
				log.WithFields("package", name).Warn("unable to extract rebar.lock metadata to add hash metadata")
				continue
			}

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
			Language:     pkg.Erlang,
			Type:         pkg.HexPkg,
			MetadataType: pkg.RebarLockMetadataType,
		}

		p := newPackage(pkg.RebarLockMetadata{
			Name:    name,
			Version: version,
		})

		names = append(names, name)
		pkgMap[sourcePkg.Name] = &p
	}

	var packages []pkg.Package
	for _, name := range names {
		p := pkgMap[name]
		p.SetID()
		packages = append(packages, *p)
	}
	return packages, nil, nil
}
