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
var _ common.ParserFn = parseMixLock

var lockDelimiter = regexp.MustCompile(`[%{}\n" ,:]+`)

// parseMixLock parses a mix.lock and returns the discovered Elixir packages.
func parseMixLock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)

	var packages []*pkg.Package
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err):
			return packages, nil, nil
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse mix.lock file: %w", err)
		}
		tokens := lockDelimiter.Split(line, -1)
		if len(tokens) < 5 {
			continue
		}
		name, version := tokens[1], tokens[4]

		packages = append(packages, &pkg.Package{
			Name:     name,
			Version:  version,
			Language: pkg.Elixir,
			Type:     pkg.MixPkg,
		})
	}
}
