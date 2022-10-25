package deb

import (
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	md5sumsExt   = ".md5sums"
	conffilesExt = ".conffiles"
	docsPath     = "/usr/share/doc"
)

func newDpkgPackage(d pkg.DpkgMetadata, dbLocation source.Location, resolver source.FileResolver, release *linux.Release) pkg.Package {
	p := pkg.Package{
		Name:         d.Package,
		Version:      d.Version,
		Locations:    source.NewLocationSet(dbLocation),
		PURL:         packageURL(d, release),
		Type:         pkg.DebPkg,
		MetadataType: pkg.DpkgMetadataType,
		Metadata:     d,
	}

	// the current entry only has what may have been listed in the status file, however, there are additional
	// files that are listed in multiple other locations. We should retrieve them all and merge the file lists
	// together.
	mergeFileListing(resolver, dbLocation, &p)

	// fetch additional data from the copyright file to derive the license information
	addLicenses(resolver, dbLocation, &p)

	p.SetID()

	return p
}

// PackageURL returns the PURL for the specific Debian package (see https://github.com/package-url/purl-spec)
func packageURL(m pkg.DpkgMetadata, distro *linux.Release) string {
	if distro == nil {
		return ""
	}

	if distro.ID != "debian" && !internal.StringInSlice("debian", distro.IDLike) {
		return ""
	}

	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.Architecture,
	}

	if m.Source != "" {
		if m.SourceVersion != "" {
			qualifiers[pkg.PURLQualifierUpstream] = fmt.Sprintf("%s@%s", m.Source, m.SourceVersion)
		} else {
			qualifiers[pkg.PURLQualifierUpstream] = m.Source
		}
	}

	return packageurl.NewPackageURL(
		packageurl.TypeDebian,
		distro.ID,
		m.Package,
		m.Version,
		pkg.PURLQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}

func addLicenses(resolver source.FileResolver, dbLocation source.Location, p *pkg.Package) {
	metadata := p.Metadata.(pkg.DpkgMetadata)

	// get license information from the copyright file
	copyrightReader, copyrightLocation := fetchCopyrightContents(resolver, dbLocation, metadata)

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
	files, infoLocations := getAdditionalFileListing(resolver, dbLocation, metadata)
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

func getAdditionalFileListing(resolver source.FileResolver, dbLocation source.Location, m pkg.DpkgMetadata) ([]pkg.DpkgFileRecord, []source.Location) {
	// ensure the default value for a collection is never nil since this may be shown as JSON
	var files = make([]pkg.DpkgFileRecord, 0)
	var locations []source.Location

	md5Reader, md5Location := fetchMd5Contents(resolver, dbLocation, m)

	if md5Reader != nil && md5Location != nil {
		defer internal.CloseAndLogError(md5Reader, md5Location.VirtualPath)
		// attach the file list
		files = append(files, parseDpkgMD5Info(md5Reader)...)

		// keep a record of the file where this was discovered
		locations = append(locations, *md5Location)
	}

	conffilesReader, conffilesLocation := fetchConffileContents(resolver, dbLocation, m)

	if conffilesReader != nil && conffilesLocation != nil {
		defer internal.CloseAndLogError(conffilesReader, conffilesLocation.VirtualPath)
		// attach the file list
		files = append(files, parseDpkgConffileInfo(conffilesReader)...)

		// keep a record of the file where this was discovered
		locations = append(locations, *conffilesLocation)
	}

	return files, locations
}

func fetchMd5Contents(resolver source.FileResolver, dbLocation source.Location, m pkg.DpkgMetadata) (io.ReadCloser, *source.Location) {
	var md5Reader io.ReadCloser
	var err error

	if resolver == nil {
		return nil, nil
	}

	parentPath := filepath.Dir(dbLocation.RealPath)

	// look for /var/lib/dpkg/info/NAME:ARCH.md5sums
	name := md5Key(m)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", name+md5sumsExt))

	if location == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.md5sums
		location = resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", m.Package+md5sumsExt))
	}

	// this is unexpected, but not a show-stopper
	if location != nil {
		md5Reader, err = resolver.FileContentsByLocation(*location)
		if err != nil {
			log.Warnf("failed to fetch deb md5 contents (package=%s): %+v", m.Package, err)
		}
	}

	return md5Reader, location
}

func fetchConffileContents(resolver source.FileResolver, dbLocation source.Location, m pkg.DpkgMetadata) (io.ReadCloser, *source.Location) {
	var reader io.ReadCloser
	var err error

	if resolver == nil {
		return nil, nil
	}

	parentPath := filepath.Dir(dbLocation.RealPath)

	// look for /var/lib/dpkg/info/NAME:ARCH.conffiles
	name := md5Key(m)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", name+conffilesExt))

	if location == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.conffiles
		location = resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", m.Package+conffilesExt))
	}

	// this is unexpected, but not a show-stopper
	if location != nil {
		reader, err = resolver.FileContentsByLocation(*location)
		if err != nil {
			log.Warnf("failed to fetch deb conffiles contents (package=%s): %+v", m.Package, err)
		}
	}

	return reader, location
}

func fetchCopyrightContents(resolver source.FileResolver, dbLocation source.Location, m pkg.DpkgMetadata) (io.ReadCloser, *source.Location) {
	if resolver == nil {
		return nil, nil
	}

	// look for /usr/share/docs/NAME/copyright files
	copyrightPath := path.Join(docsPath, m.Package, "copyright")
	location := resolver.RelativeFileByPath(dbLocation, copyrightPath)

	// we may not have a copyright file for each package, ignore missing files
	if location == nil {
		return nil, nil
	}

	reader, err := resolver.FileContentsByLocation(*location)
	if err != nil {
		log.Warnf("failed to fetch deb copyright contents (package=%s): %w", m.Package, err)
	}

	return reader, location
}

func md5Key(metadata pkg.DpkgMetadata) string {
	contentKey := metadata.Package
	if metadata.Architecture != "" && metadata.Architecture != "all" {
		contentKey = contentKey + ":" + metadata.Architecture
	}
	return contentKey
}
