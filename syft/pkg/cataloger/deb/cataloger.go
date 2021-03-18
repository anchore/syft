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
	md5sumsExt = ".md5sums"
	docsPath   = "/usr/share/doc"
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
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, error) {
	dbFileMatches, err := resolver.FilesByGlob(pkg.DpkgDbGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to find dpkg status files's by glob: %w", err)
	}

	var results []pkg.Package
	var pkgs []pkg.Package
	for _, dbLocation := range dbFileMatches {
		dbContents, err := resolver.FileContentsByLocation(dbLocation)
		if err != nil {
			return nil, err
		}

		pkgs, err = parseDpkgStatus(dbContents)
		if err != nil {
			return nil, fmt.Errorf("unable to catalog dpkg package=%+v: %w", dbLocation.RealPath, err)
		}

		for i := range pkgs {
			p := &pkgs[i]
			p.FoundBy = c.Name()
			p.Locations = []source.Location{dbLocation}

			metadata := p.Metadata.(pkg.DpkgMetadata)

			md5Reader, md5Location, err := fetchMd5Contents(resolver, dbLocation, p)
			if err != nil {
				return nil, fmt.Errorf("unable to find dpkg md5 contents: %w", err)
			}

			if md5Reader != nil {
				// attach the file list
				metadata.Files = parseDpkgMD5Info(md5Reader)

				// keep a record of the file where this was discovered
				if md5Location != nil {
					p.Locations = append(p.Locations, *md5Location)
				}
			} else {
				// ensure the file list is an empty collection (not nil)
				metadata.Files = make([]pkg.DpkgFileRecord, 0)
			}

			// persist alterations
			p.Metadata = metadata

			// get license information from the copyright file
			copyrightReader, copyrightLocation, err := fetchCopyrightContents(resolver, dbLocation, p)
			if err != nil {
				return nil, fmt.Errorf("unable to find dpkg copyright contents: %w", err)
			}

			if copyrightReader != nil {
				// attach the licenses
				p.Licenses = parseLicensesFromCopyright(copyrightReader)

				// keep a record of the file where this was discovered
				if copyrightLocation != nil {
					p.Locations = append(p.Locations, *copyrightLocation)
				}
			}
		}

		results = append(results, pkgs...)
	}
	return results, nil
}

func fetchMd5Contents(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) (io.Reader, *source.Location, error) {
	parentPath := filepath.Dir(dbLocation.RealPath)

	// look for /var/lib/dpkg/info/NAME:ARCH.md5sums
	name := md5Key(p)
	md5SumLocation := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", name+md5sumsExt))

	if md5SumLocation == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.md5sums
		md5SumLocation = resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", p.Name+md5sumsExt))
	}

	// this is unexpected, but not a show-stopper
	if md5SumLocation == nil {
		return nil, nil, nil
	}

	reader, err := resolver.FileContentsByLocation(*md5SumLocation)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch deb md5 contents (%+v): %w", p, err)
	}
	return reader, md5SumLocation, nil
}

func fetchCopyrightContents(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) (io.Reader, *source.Location, error) {
	// look for /usr/share/docs/NAME/copyright files
	name := p.Name
	copyrightPath := path.Join(docsPath, name, "copyright")
	copyrightLocation := resolver.RelativeFileByPath(dbLocation, copyrightPath)

	// we may not have a copyright file for each package, ignore missing files
	if copyrightLocation == nil {
		return nil, nil, nil
	}

	reader, err := resolver.FileContentsByLocation(*copyrightLocation)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch deb copyright contents (%+v): %w", p, err)
	}

	return reader, copyrightLocation, nil
}

func md5Key(p *pkg.Package) string {
	metadata := p.Metadata.(pkg.DpkgMetadata)

	contentKey := p.Name
	if metadata.Architecture != "" && metadata.Architecture != "all" {
		contentKey = contentKey + ":" + metadata.Architecture
	}
	return contentKey
}
