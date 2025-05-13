package gentoo

import (
	"bufio"
	"context"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var (
	cpvRe                = regexp.MustCompile(`/([^/]*/[\w+][\w+-]*)-((\d+)((\.\d+)*)([a-z]?)((_(pre|p|beta|alpha|rc)\d*)*)(-r\d+)?)/CONTENTS$`)
	_     generic.Parser = parsePortageContents
)

// parses individual CONTENTS files from the portage flat-file store (e.g. /var/db/pkg/*/*/CONTENTS).
func parsePortageContents(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	cpvMatch := cpvRe.FindStringSubmatch(reader.RealPath)
	if cpvMatch == nil {
		return nil, nil, fmt.Errorf("failed to match package and version in %s", reader.RealPath)
	}

	name, version := cpvMatch[1], cpvMatch[2]
	if name == "" || version == "" {
		log.WithFields("path", reader.RealPath).Debug("failed to parse portage name and version")
		return nil, nil, fmt.Errorf("failed to parse portage name and version")
	}

	m := pkg.PortageEntry{
		// ensure the default value for a collection is never nil since this may be shown as JSON
		Files: make([]pkg.PortageFileRecord, 0),
	}

	locations := file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	licenses, licenseLocations := addLicenses(ctx, resolver, reader.Location, &m)
	locations.Add(licenseLocations...)
	locations.Add(addSize(resolver, reader.Location, &m)...)
	addFiles(resolver, reader.Location, &m)

	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      packageURL(name, version),
		Locations: locations,
		Licenses:  licenses,
		Type:      pkg.PortagePkg,
		Metadata:  m,
	}
	p.SetID()

	return []pkg.Package{p}, nil, nil
}

func addFiles(resolver file.Resolver, dbLocation file.Location, entry *pkg.PortageEntry) {
	contentsReader, err := resolver.FileContentsByLocation(dbLocation)
	if err != nil {
		log.WithFields("path", dbLocation.RealPath, "error", err).Debug("failed to fetch portage contents")
		return
	}
	defer internal.CloseAndLogError(contentsReader, dbLocation.RealPath)

	scanner := bufio.NewScanner(contentsReader)
	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), "\n")
		fields := strings.Split(line, " ")

		if fields[0] == "obj" {
			record := pkg.PortageFileRecord{
				Path: fields[1],
			}
			record.Digest = &file.Digest{
				Algorithm: "md5",
				Value:     fields[2],
			}
			entry.Files = append(entry.Files, record)
		}
	}
}

func addLicenses(ctx context.Context, resolver file.Resolver, dbLocation file.Location, entry *pkg.PortageEntry) (pkg.LicenseSet, []file.Location) {
	parentPath := filepath.Dir(dbLocation.RealPath)

	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "LICENSE"))

	if location == nil {
		return pkg.NewLicenseSet(), nil
	}

	licenseReader, err := resolver.FileContentsByLocation(*location)
	if err != nil {
		log.WithFields("path", dbLocation.RealPath, "error", err).Debug("failed to fetch portage LICENSE")
		return pkg.NewLicenseSet(), nil
	}
	defer internal.CloseAndLogError(licenseReader, location.RealPath)

	og, spdxExpression := extractLicenses(resolver, location, licenseReader)
	entry.Licenses = og

	return pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, spdxExpression, *location)), []file.Location{
		location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)}
}

func addSize(resolver file.Resolver, dbLocation file.Location, entry *pkg.PortageEntry) []file.Location {
	parentPath := filepath.Dir(dbLocation.RealPath)

	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "SIZE"))

	if location == nil {
		return nil
	}

	sizeReader, err := resolver.FileContentsByLocation(*location)
	if err != nil {
		log.WithFields("path", dbLocation.RealPath, "error", err).Debug("failed to fetch portage SIZE")
		return nil
	}
	defer internal.CloseAndLogError(sizeReader, location.RealPath)

	scanner := bufio.NewScanner(sizeReader)
	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), "\n")
		size, err := strconv.Atoi(line)
		if err == nil {
			entry.InstalledSize = size
		}
	}

	return []file.Location{location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)}
}
