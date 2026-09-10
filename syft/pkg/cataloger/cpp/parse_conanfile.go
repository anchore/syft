package cpp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseConanfile

// parseConanfile is a parser function for conanfile.txt contents, returning all packages discovered.
func parseConanfile(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)
	inRequirements := false
	var pkgs []pkg.Package
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(err, io.EOF):
			return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse conanfile.txt file: %w", err)
		}

		trimmed := strings.TrimSpace(line)

		// skip blank lines and comments without affecting section state
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		switch {
		case strings.Contains(line, "[requires]"):
			inRequirements = true
			continue
		case strings.ContainsAny(line, "[]"):
			inRequirements = false
			continue
		}

		if !inRequirements {
			continue
		}

		p := newConanfilePackage(
			pkg.ConanfileEntry{Ref: trimmed},
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		if p == nil {
			continue
		}

		pkgs = append(pkgs, *p)
	}
}
