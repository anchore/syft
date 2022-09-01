/*
Package dpkg provides a concrete Cataloger implementation for Debian package DB status files.
*/
package deb

import (
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	md5sumsExt   = ".md5sums"
	conffilesExt = ".conffiles"
	docsPath     = "/usr/share/doc"
)

type Cataloger struct{}

// NewDpkgdbCataloger returns a new Deb package cataloger object.
func NewDpkgdbCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return "dpkgdb-cataloger"
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing dpkg support files.
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	dbFileMatches, err := resolver.FilesByGlob(pkg.DpkgDBGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find dpkg status files's by glob: %w", err)
	}

	var allPackages []pkg.Package
	for _, dbLocation := range dbFileMatches {
		dbContents, err := resolver.FileContentsByLocation(dbLocation)
		if err != nil {
			return nil, nil, err
		}

		pkgs, err := parseDpkgStatus(dbContents)
		internal.CloseAndLogError(dbContents, dbLocation.VirtualPath)
		if err != nil {
			log.Warnf("dpkg cataloger: unable to catalog package=%+v: %w", dbLocation.RealPath, err)
			continue
		}

		for i := range pkgs {
			p := &pkgs[i]
			p.FoundBy = c.Name()
			p.Locations.Add(dbLocation)

			// the current entry only has what may have been listed in the status file, however, there are additional
			// files that are listed in multiple other locations. We should retrieve them all and merge the file lists
			// together.
			mergeFileListing(resolver, dbLocation, p)

			// fetch additional data from the copyright file to derive the license information
			addLicenses(resolver, dbLocation, p)

			p.SetID()
		}

		allPackages = append(allPackages, pkgs...)
	}
	return allPackages, nil, nil
}

func addLicenses(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) {
	// get license information from the copyright file
	copyrightReader, copyrightLocation := fetchCopyrightContents(resolver, dbLocation, p)

	if copyrightReader != nil && copyrightLocation != nil {
		defer internal.CloseAndLogError(copyrightReader, copyrightLocation.VirtualPath)
		// attach the licenses
		p.Licenses = parseLicensesFromCopyright(copyrightReader)

		// keep a record of the file where this was discovered
		p.Locations.Add(*copyrightLocation)
	}
}

func mergeFileListing(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) {
	metadata := p.Metadata.(pkg.DpkgMetadata)

	// get file listing (package files + additional config files)
	files, infoLocations := getAdditionalFileListing(resolver, dbLocation, p)
loopNewFiles:
	for _, newFile := range files {
		for _, existingFile := range metadata.Files {
			if existingFile.Path == newFile.Path {
				// skip adding this file since it already exists
				continue loopNewFiles
			}
		}
		metadata.Files = append(metadata.Files, newFile)
	}

	// sort files by path
	sort.SliceStable(metadata.Files, func(i, j int) bool {
		return metadata.Files[i].Path < metadata.Files[j].Path
	})

	// persist alterations
	p.Metadata = metadata

	// persist location information from each new source of information
	p.Locations.Add(infoLocations...)
}

func getAdditionalFileListing(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) ([]pkg.DpkgFileRecord, []source.Location) {
	// ensure the default value for a collection is never nil since this may be shown as JSON
	var files = make([]pkg.DpkgFileRecord, 0)
	var locations []source.Location

	md5Reader, md5Location := fetchMd5Contents(resolver, dbLocation, p)

	if md5Reader != nil && md5Location != nil {
		defer internal.CloseAndLogError(md5Reader, md5Location.VirtualPath)
		// attach the file list
		files = append(files, parseDpkgMD5Info(md5Reader)...)

		// keep a record of the file where this was discovered
		locations = append(locations, *md5Location)
	}

	conffilesReader, conffilesLocation := fetchConffileContents(resolver, dbLocation, p)

	if conffilesReader != nil && conffilesLocation != nil {
		defer internal.CloseAndLogError(conffilesReader, conffilesLocation.VirtualPath)
		// attach the file list
		files = append(files, parseDpkgConffileInfo(conffilesReader)...)

		// keep a record of the file where this was discovered
		locations = append(locations, *conffilesLocation)
	}

	return files, locations
}

func fetchMd5Contents(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) (io.ReadCloser, *source.Location) {
	var md5Reader io.ReadCloser
	var err error

	parentPath := filepath.Dir(dbLocation.RealPath)

	// look for /var/lib/dpkg/info/NAME:ARCH.md5sums
	name := md5Key(p)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", name+md5sumsExt))

	if location == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.md5sums
		location = resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", p.Name+md5sumsExt))
	}

	// this is unexpected, but not a show-stopper
	if location != nil {
		md5Reader, err = resolver.FileContentsByLocation(*location)
		if err != nil {
			log.Warnf("failed to fetch deb md5 contents (package=%s): %+v", p.Name, err)
		}
	}

	return md5Reader, location
}

func fetchConffileContents(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) (io.ReadCloser, *source.Location) {
	var reader io.ReadCloser
	var err error

	parentPath := filepath.Dir(dbLocation.RealPath)

	// look for /var/lib/dpkg/info/NAME:ARCH.conffiles
	name := md5Key(p)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", name+conffilesExt))

	if location == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.conffiles
		location = resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", p.Name+conffilesExt))
	}

	// this is unexpected, but not a show-stopper
	if location != nil {
		reader, err = resolver.FileContentsByLocation(*location)
		if err != nil {
			log.Warnf("failed to fetch deb conffiles contents (package=%s): %+v", p.Name, err)
		}
	}

	return reader, location
}

func fetchCopyrightContents(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) (io.ReadCloser, *source.Location) {
	// look for /usr/share/docs/NAME/copyright files
	name := p.Name
	copyrightPath := path.Join(docsPath, name, "copyright")
	location := resolver.RelativeFileByPath(dbLocation, copyrightPath)

	// we may not have a copyright file for each package, ignore missing files
	if location == nil {
		return nil, nil
	}

	reader, err := resolver.FileContentsByLocation(*location)
	if err != nil {
		log.Warnf("failed to fetch deb copyright contents (package=%s): %w", p.Name, err)
	}

	return reader, location
}

func md5Key(p *pkg.Package) string {
	metadata := p.Metadata.(pkg.DpkgMetadata)

	contentKey := p.Name
	if metadata.Architecture != "" && metadata.Architecture != "all" {
		contentKey = contentKey + ":" + metadata.Architecture
	}
	return contentKey
}
