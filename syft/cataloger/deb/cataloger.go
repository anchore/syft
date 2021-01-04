/*
Package dpkg provides a concrete Cataloger implementation for Debian package DB status files.
*/
package deb

import (
	"fmt"
	"io"
	"path"
	"path/filepath"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	dpkgStatusGlob = "**/var/lib/dpkg/status"
	md5sumsExt     = ".md5sums"
	docsPath       = "/usr/share/doc"
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
// nolint:funlen
func (c *Cataloger) Catalog(resolver source.Resolver) ([]pkg.Package, error) {
	dbFileMatches, err := resolver.FilesByGlob(dpkgStatusGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to find dpkg status files's by glob: %w", err)
	}

	var pkgs []pkg.Package
	for _, dbLocation := range dbFileMatches {
		dbContents, err := resolver.FileContentsByLocation(dbLocation)
		if err != nil {
			return nil, err
		}

		pkgs, err = parseDpkgStatus(dbContents)
		if err != nil {
			return nil, fmt.Errorf("unable to catalog dpkg package=%+v: %w", dbLocation.Path, err)
		}

		md5ContentsByName, md5RefsByName, err := fetchMd5Contents(resolver, dbLocation, pkgs)
		if err != nil {
			return nil, fmt.Errorf("unable to find dpkg md5 contents: %w", err)
		}

		copyrightContentsByName, copyrightRefsByName, err := fetchCopyrightContents(resolver, dbLocation, pkgs)
		if err != nil {
			return nil, fmt.Errorf("unable to find dpkg copyright contents: %w", err)
		}

		for i := range pkgs {
			p := &pkgs[i]
			p.FoundBy = c.Name()
			p.Locations = []source.Location{dbLocation}

			metadata := p.Metadata.(pkg.DpkgMetadata)

			if md5Reader, ok := md5ContentsByName[md5Key(*p)]; ok {
				// attach the file list
				metadata.Files = parseDpkgMD5Info(md5Reader)

				// keep a record of the file where this was discovered
				if ref, ok := md5RefsByName[md5Key(*p)]; ok {
					p.Locations = append(p.Locations, ref)
				}
			} else {
				// ensure the file list is an empty collection (not nil)
				metadata.Files = make([]pkg.DpkgFileRecord, 0)
			}

			// persist alterations
			p.Metadata = metadata

			copyrightReader, ok := copyrightContentsByName[p.Name]
			if ok {
				// attach the licenses
				p.Licenses = parseLicensesFromCopyright(copyrightReader)

				// keep a record of the file where this was discovered
				if ref, ok := copyrightRefsByName[p.Name]; ok {
					p.Locations = append(p.Locations, ref)
				}
			}
		}
	}
	return pkgs, nil
}

func fetchMd5Contents(resolver source.Resolver, dbLocation source.Location, pkgs []pkg.Package) (map[string]io.Reader, map[string]source.Location, error) {
	// fetch all MD5 file contents. This approach is more efficient than fetching each MD5 file one at a time

	var md5FileMatches []source.Location
	var nameByRef = make(map[source.Location]string)
	parentPath := filepath.Dir(dbLocation.Path)

	for _, p := range pkgs {
		// look for /var/lib/dpkg/info/NAME:ARCH.md5sums
		name := md5Key(p)
		md5sumPath := path.Join(parentPath, "info", name+md5sumsExt)
		md5SumLocation := resolver.RelativeFileByPath(dbLocation, md5sumPath)

		if md5SumLocation == nil {
			// the most specific key did not work, fallback to just the name
			// look for /var/lib/dpkg/info/NAME.md5sums
			name := p.Name
			md5sumPath := path.Join(parentPath, "info", name+md5sumsExt)
			md5SumLocation = resolver.RelativeFileByPath(dbLocation, md5sumPath)
		}
		// we should have at least one reference
		if md5SumLocation != nil {
			md5FileMatches = append(md5FileMatches, *md5SumLocation)
			nameByRef[*md5SumLocation] = name
		}
	}

	// fetch the md5 contents
	md5ContentsByLocation, err := resolver.MultipleFileContentsByLocation(md5FileMatches)
	if err != nil {
		return nil, nil, err
	}

	// organize content results and refs by a combination of name and architecture
	var contentsByName = make(map[string]io.Reader)
	var refsByName = make(map[string]source.Location)
	for location, contents := range md5ContentsByLocation {
		name := nameByRef[location]
		contentsByName[name] = contents
		refsByName[name] = location
	}

	return contentsByName, refsByName, nil
}

func fetchCopyrightContents(resolver source.Resolver, dbLocation source.Location, pkgs []pkg.Package) (map[string]io.Reader, map[string]source.Location, error) {
	// fetch all copyright file contents. This approach is more efficient than fetching each copyright file one at a time

	var copyrightFileMatches []source.Location
	var nameByLocation = make(map[source.Location]string)
	for _, p := range pkgs {
		// look for /usr/share/docs/NAME/copyright files
		name := p.Name
		copyrightPath := path.Join(docsPath, name, "copyright")
		copyrightLocation := resolver.RelativeFileByPath(dbLocation, copyrightPath)

		// we may not have a copyright file for each package, ignore missing files
		if copyrightLocation != nil {
			copyrightFileMatches = append(copyrightFileMatches, *copyrightLocation)
			nameByLocation[*copyrightLocation] = name
		}
	}

	// fetch the copyright contents
	copyrightContentsByLocation, err := resolver.MultipleFileContentsByLocation(copyrightFileMatches)
	if err != nil {
		return nil, nil, err
	}

	// organize content results and refs by package name
	var contentsByName = make(map[string]io.Reader)
	var refsByName = make(map[string]source.Location)
	for location, contents := range copyrightContentsByLocation {
		name := nameByLocation[location]
		contentsByName[name] = contents
		refsByName[name] = location
	}

	return contentsByName, refsByName, nil
}

func md5Key(p pkg.Package) string {
	metadata := p.Metadata.(pkg.DpkgMetadata)

	contentKey := p.Name
	if metadata.Architecture != "" && metadata.Architecture != "all" {
		contentKey = contentKey + ":" + metadata.Architecture
	}
	return contentKey
}
