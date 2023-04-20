package rpm

import (
	"bufio"
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
func parseRpmManifest(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
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

		p, err := parseRpmManifestEntry(strings.TrimSuffix(line, "\n"), reader.Location)
		if err != nil {
			log.Warnf("unable to parse RPM manifest entry: %w", err)
			continue
		}

		if !pkg.IsValid(p) {
			continue
		}

		p.SetID()
		allPkgs = append(allPkgs, *p)
	}

	return allPkgs, nil, nil
}

// Parses an entry in an RPM manifest file as used in Mariner distroless containers
// Each line is the output of :
// rpm --query --all --query-format "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n"
// https://github.com/microsoft/CBL-Mariner/blob/3df18fac373aba13a54bd02466e64969574f13af/toolkit/docs/how_it_works/5_misc.md?plain=1#L150
func parseRpmManifestEntry(entry string, location file.Location) (*pkg.Package, error) {
	metadata, err := newMetadataFromManifestLine(entry)
	if err != nil {
		return nil, err
	}

	if metadata == nil {
		return nil, nil
	}

	p := newPackage(location, *metadata, nil)

	return &p, nil
}
