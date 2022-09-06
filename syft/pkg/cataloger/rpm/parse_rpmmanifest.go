package rpm

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Parses an entry in an RPM manifest file as used in Mariner distroless containers
// Each line is the output of :
// rpm --query --all --query-format "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n"
// https://github.com/microsoft/CBL-Mariner/blob/3df18fac373aba13a54bd02466e64969574f13af/toolkit/docs/how_it_works/5_misc.md?plain=1#L150
func parseRpmManifestEntry(entry string, location source.Location) (*pkg.Package, error) {
	parts := strings.Split(entry, "\t")
	if len(parts) < 10 {
		return nil, fmt.Errorf("unexpected number of fields in line: %s", entry)
	}

	versionParts := strings.Split(parts[1], "-")
	if len(versionParts) != 2 {
		return nil, fmt.Errorf("unexpected version field: %s", parts[1])
	}
	version := versionParts[0]
	release := versionParts[1]

	converted, err := strconv.Atoi(parts[8])
	var epoch *int
	if err != nil || parts[5] == "(none)" {
		epoch = nil
	} else {
		epoch = &converted
	}

	converted, err = strconv.Atoi(parts[6])
	var size int
	if err == nil {
		size = converted
	}

	metadata := pkg.RpmMetadata{
		Name:      parts[0],
		Version:   version,
		Epoch:     epoch,
		Arch:      parts[7],
		Release:   release,
		SourceRpm: parts[9],
		Vendor:    parts[4],
		Size:      size,
	}

	p := pkg.Package{
		Name:         parts[0],
		Version:      toELVersion(metadata),
		Locations:    source.NewLocationSet(location),
		FoundBy:      dbCatalogerName,
		Type:         pkg.RpmPkg,
		MetadataType: pkg.RpmMetadataType,
		Metadata:     metadata,
	}

	p.SetID()
	return &p, nil
}

// Parses an RPM manifest file, as used in Mariner distroless containers, and returns the Packages listed
func parseRpmManifest(dbLocation source.Location, reader io.Reader) ([]pkg.Package, error) {
	r := bufio.NewReader(reader)
	allPkgs := make([]pkg.Package, 0)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if line == "" {
			continue
		}

		p, err := parseRpmManifestEntry(strings.TrimSuffix(line, "\n"), dbLocation)
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

	return allPkgs, nil
}
