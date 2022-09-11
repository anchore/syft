/*
Package portage provides a concrete Cataloger implementation for Gentoo Portage.
*/
package portage

import (
	"bufio"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var (
	cpvRe = regexp.MustCompile(`/([^/]*/[\w+][\w+-]*)-((\d+)((\.\d+)*)([a-z]?)((_(pre|p|beta|alpha|rc)\d*)*)(-r\d+)?)/CONTENTS$`)
)

type Cataloger struct{}

// NewPortageCataloger returns a new Portage package cataloger object.
func NewPortageCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return "portage-cataloger"
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing portage support files.
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	dbFileMatches, err := resolver.FilesByGlob(pkg.PortageDBGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find portage files by glob: %w", err)
	}
	var allPackages []pkg.Package
	for _, dbLocation := range dbFileMatches {
		cpvMatch := cpvRe.FindStringSubmatch(dbLocation.RealPath)
		if cpvMatch == nil {
			return nil, nil, fmt.Errorf("failed to match package and version in %s", dbLocation.RealPath)
		}
		entry := pkg.PortageMetadata{
			// ensure the default value for a collection is never nil since this may be shown as JSON
			Files:   make([]pkg.PortageFileRecord, 0),
			Package: cpvMatch[1],
			Version: cpvMatch[2],
		}

		err = addFiles(resolver, dbLocation, &entry)
		if err != nil {
			return nil, nil, err
		}

		addSize(resolver, dbLocation, &entry)

		p := pkg.Package{
			Name:         entry.Package,
			Version:      entry.Version,
			Type:         pkg.PortagePkg,
			MetadataType: pkg.PortageMetadataType,
			Metadata:     entry,
		}
		addLicenses(resolver, dbLocation, &p)
		p.FoundBy = c.Name()
		p.Locations.Add(dbLocation)
		p.SetID()
		allPackages = append(allPackages, p)
	}
	return allPackages, nil, nil
}

func addFiles(resolver source.FileResolver, dbLocation source.Location, entry *pkg.PortageMetadata) error {
	contentsReader, err := resolver.FileContentsByLocation(dbLocation)
	if err != nil {
		return err
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
	return nil
}

func addLicenses(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) {
	parentPath := filepath.Dir(dbLocation.RealPath)

	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "LICENSE"))

	if location != nil {
		licenseReader, err := resolver.FileContentsByLocation(*location)
		if err == nil {
			findings := internal.NewStringSet()
			scanner := bufio.NewScanner(licenseReader)
			scanner.Split(bufio.ScanWords)
			for scanner.Scan() {
				token := scanner.Text()
				if token != "||" && token != "(" && token != ")" {
					findings.Add(token)
				}
			}
			p.Licenses = findings.ToSlice()

			sort.Strings(p.Licenses)
		}
	}
}

func addSize(resolver source.FileResolver, dbLocation source.Location, entry *pkg.PortageMetadata) {
	parentPath := filepath.Dir(dbLocation.RealPath)

	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "SIZE"))

	if location != nil {
		sizeReader, err := resolver.FileContentsByLocation(*location)
		if err != nil {
			log.Warnf("failed to fetch portage SIZE (package=%s): %+v", entry.Package, err)
		} else {
			scanner := bufio.NewScanner(sizeReader)
			for scanner.Scan() {
				line := strings.Trim(scanner.Text(), "\n")
				size, err := strconv.Atoi(line)
				if err == nil {
					entry.InstalledSize = size
				}
			}
		}
	}
}
