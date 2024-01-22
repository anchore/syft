package redhat

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// Parses an RPM manifest file, as used in Mariner distroless containers, and returns the Packages listed
func parseRpmManifest(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)
	allPkgs := make([]pkg.Package, 0)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, nil, err
		}

		if line == "" {
			continue
		}

		metadata, err := newMetadataFromManifestLine(strings.TrimSuffix(line, "\n"))
		if err != nil {
			log.Warnf("unable to parse RPM manifest entry: %+v", err)
			continue
		}

		if metadata == nil {
			log.Warn("unable to parse RPM manifest entry: no metadata found")
			continue
		}

		p := newDBPackage(reader.Location, *metadata, nil, nil)

		if !pkg.IsValid(&p) {
			continue
		}

		p.SetID()
		allPkgs = append(allPkgs, p)
	}

	return allPkgs, nil, nil
}
