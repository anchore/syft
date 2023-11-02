package gentoo

import (
	"bufio"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/scylladb/go-set/strset"

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
func parsePortageContents(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	cpvMatch := cpvRe.FindStringSubmatch(reader.Location.RealPath)
	if cpvMatch == nil {
		return nil, nil, fmt.Errorf("failed to match package and version in %s", reader.Location.RealPath)
	}

	name, version := cpvMatch[1], cpvMatch[2]
	if name == "" || version == "" {
		log.WithFields("path", reader.Location.RealPath).Warnf("failed to parse portage name and version")
		return nil, nil, nil
	}

	p := pkg.Package{
		Name:    name,
		Version: version,
		PURL:    packageURL(name, version),
		Locations: file.NewLocationSet(
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type: pkg.PortagePkg,
		Metadata: pkg.PortageEntry{
			// ensure the default value for a collection is never nil since this may be shown as JSON
			Files: make([]pkg.PortageFileRecord, 0),
		},
	}
	addLicenses(resolver, reader.Location, &p)
	addSize(resolver, reader.Location, &p)
	addFiles(resolver, reader.Location, &p)

	p.SetID()

	return []pkg.Package{p}, nil, nil
}

func addFiles(resolver file.Resolver, dbLocation file.Location, p *pkg.Package) {
	contentsReader, err := resolver.FileContentsByLocation(dbLocation)
	if err != nil {
		log.WithFields("path", dbLocation.RealPath).Warnf("failed to fetch portage contents (package=%s): %+v", p.Name, err)
		return
	}

	entry, ok := p.Metadata.(pkg.PortageEntry)
	if !ok {
		return
	}

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

	p.Metadata = entry
	p.Locations.Add(dbLocation)
}

func addLicenses(resolver file.Resolver, dbLocation file.Location, p *pkg.Package) {
	parentPath := filepath.Dir(dbLocation.RealPath)

	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "LICENSE"))

	if location == nil {
		return
	}

	licenseReader, err := resolver.FileContentsByLocation(*location)
	if err != nil {
		log.WithFields("path", dbLocation.RealPath).Warnf("failed to fetch portage LICENSE: %+v", err)
		return
	}

	findings := strset.New()
	scanner := bufio.NewScanner(licenseReader)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		token := scanner.Text()
		if token != "||" && token != "(" && token != ")" {
			findings.Add(token)
		}
	}

	licenseCandidates := findings.List()
	p.Licenses = pkg.NewLicenseSet(pkg.NewLicensesFromLocation(*location, licenseCandidates...)...)
	p.Locations.Add(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
}

func addSize(resolver file.Resolver, dbLocation file.Location, p *pkg.Package) {
	parentPath := filepath.Dir(dbLocation.RealPath)

	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "SIZE"))

	if location == nil {
		return
	}

	entry, ok := p.Metadata.(pkg.PortageEntry)
	if !ok {
		return
	}

	sizeReader, err := resolver.FileContentsByLocation(*location)
	if err != nil {
		log.WithFields("name", p.Name).Warnf("failed to fetch portage SIZE: %+v", err)
		return
	}

	scanner := bufio.NewScanner(sizeReader)
	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), "\n")
		size, err := strconv.Atoi(line)
		if err == nil {
			entry.InstalledSize = size
		}
	}

	p.Metadata = entry
	p.Locations.Add(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
}
