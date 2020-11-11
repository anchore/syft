/*
Package dpkg provides a concrete Cataloger implementation for Debian package DB status files.
*/
package deb

import (
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
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
func (c *Cataloger) Catalog(resolver scope.Resolver) ([]pkg.Package, error) {
	dbFileMatches, err := resolver.FilesByGlob(dpkgStatusGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to find dpkg status files's by glob: %w", err)
	}

	var pkgs []pkg.Package
	for _, dbRef := range dbFileMatches {
		dbContents, err := resolver.FileContentsByRef(dbRef)
		if err != nil {
			return nil, err
		}

		pkgs, err = parseDpkgStatus(strings.NewReader(dbContents))
		if err != nil {
			return nil, fmt.Errorf("unable to catalog dpkg package=%+v: %w", dbRef.Path, err)
		}

		md5ContentsByName, md5RefsByName, err := fetchMd5Contents(resolver, dbRef, pkgs)
		if err != nil {
			return nil, fmt.Errorf("unable to find dpkg md5 contents: %w", err)
		}

		copyrightContentsByName, copyrightRefsByName, err := fetchCopyrightContents(resolver, dbRef, pkgs)
		if err != nil {
			return nil, fmt.Errorf("unable to find dpkg copyright contents: %w", err)
		}

		for i := range pkgs {
			p := &pkgs[i]
			p.FoundBy = c.Name()
			p.Source = []file.Reference{dbRef}

			if md5Reader, ok := md5ContentsByName[md5Key(*p)]; ok {
				// attach the file list
				metadata := p.Metadata.(pkg.DpkgMetadata)
				metadata.Files = parseDpkgMD5Info(md5Reader)
				p.Metadata = metadata

				// keep a record of the file where this was discovered
				if ref, ok := md5RefsByName[md5Key(*p)]; ok {
					p.Source = append(p.Source, ref)
				}
			}

			copyrightReader, ok := copyrightContentsByName[p.Name]
			if ok {
				// attach the licenses
				p.Licenses = parseLicensesFromCopyright(copyrightReader)

				// keep a record of the file where this was discovered
				if ref, ok := copyrightRefsByName[p.Name]; ok {
					p.Source = append(p.Source, ref)
				}
			}
		}
	}
	return pkgs, nil
}

func fetchMd5Contents(resolver scope.Resolver, dbRef file.Reference, pkgs []pkg.Package) (map[string]io.Reader, map[string]file.Reference, error) {
	// fetch all MD5 file contents. This approach is more efficient than fetching each MD5 file one at a time

	var md5FileMatches []file.Reference
	var nameByRef = make(map[file.Reference]string)
	parentPath, err := dbRef.Path.ParentPath()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find parent of path=%+v: %w", dbRef.Path, err)
	}
	for _, p := range pkgs {
		// look for /var/lib/dpkg/info/NAME:ARCH.md5sums
		name := md5Key(p)
		md5sumPath := path.Join(string(parentPath), "info", name+md5sumsExt)
		md5SumRef, err := resolver.RelativeFileByPath(dbRef, md5sumPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to find relative md5sum from path=%+v: %w", dbRef.Path, err)
		}

		if md5SumRef == nil {
			// the most specific key did not work, fallback to just the name
			// look for /var/lib/dpkg/info/NAME.md5sums
			name := p.Name
			md5sumPath := path.Join(string(parentPath), "info", name+md5sumsExt)
			md5SumRef, err = resolver.RelativeFileByPath(dbRef, md5sumPath)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to find relative md5sum from path=%+v: %w", dbRef.Path, err)
			}
		}
		// we should have at least one reference
		if md5SumRef != nil {
			md5FileMatches = append(md5FileMatches, *md5SumRef)
			nameByRef[*md5SumRef] = name
		}
	}

	// fetch the md5 contents
	md5ContentsByRef, err := resolver.MultipleFileContentsByRef(md5FileMatches...)
	if err != nil {
		return nil, nil, err
	}

	// organize content results and refs by a combination of name and architecture
	var contentsByName = make(map[string]io.Reader)
	var refsByName = make(map[string]file.Reference)
	for ref, contents := range md5ContentsByRef {
		name := nameByRef[ref]
		contentsByName[name] = strings.NewReader(contents)
		refsByName[name] = ref
	}

	return contentsByName, refsByName, nil
}

func fetchCopyrightContents(resolver scope.Resolver, dbRef file.Reference, pkgs []pkg.Package) (map[string]io.Reader, map[string]file.Reference, error) {
	// fetch all copyright file contents. This approach is more efficient than fetching each copyright file one at a time

	var copyrightFileMatches []file.Reference
	var nameByRef = make(map[file.Reference]string)
	for _, p := range pkgs {
		// look for /usr/share/docs/NAME/copyright files
		name := p.Name
		copyrightPath := path.Join(docsPath, name, "copyright")
		copyrightRef, err := resolver.RelativeFileByPath(dbRef, copyrightPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to find relative copyright from path=%+v: %w", dbRef.Path, err)
		}

		// we may not have a copyright file for each package, ignore missing files
		if copyrightRef != nil {
			copyrightFileMatches = append(copyrightFileMatches, *copyrightRef)
			nameByRef[*copyrightRef] = name
		}
	}

	// fetch the copyright contents
	copyrightContentsByRef, err := resolver.MultipleFileContentsByRef(copyrightFileMatches...)
	if err != nil {
		return nil, nil, err
	}

	// organize content results and refs by package name
	var contentsByName = make(map[string]io.Reader)
	var refsByName = make(map[string]file.Reference)
	for ref, contents := range copyrightContentsByRef {
		name := nameByRef[ref]
		contentsByName[name] = strings.NewReader(contents)
		refsByName[name] = ref
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
