package javascript

import (
	"encoding/json"
	"io"
	"path"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackageJSONPackage(u packageJSON, locations ...source.Location) pkg.Package {
	licenses, err := u.licensesFromJSON()
	if err != nil {
		log.Warnf("unable to extract licenses from javascript package.json: %+v", err)
	}

	p := pkg.Package{
		Name:         u.Name,
		Version:      u.Version,
		Licenses:     internal.LogicalStrings{Simple: licenses},
		PURL:         packageURL(u.Name, u.Version),
		Locations:    source.NewLocationSet(locations...),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageJSONMetadataType,
		Metadata: pkg.NpmPackageJSONMetadata{
			Name:     u.Name,
			Version:  u.Version,
			Author:   u.Author.AuthorString(),
			Homepage: u.Homepage,
			URL:      u.Repository.URL,
			Licenses: licenses,
			Private:  u.Private,
		},
	}

	p.SetID()

	return p
}

func newPackageLockV1Package(resolver source.FileResolver, location source.Location, name string, u lockDependency) pkg.Package {
	version := u.Version

	const aliasPrefixPackageLockV1 = "npm:"

	// Handles type aliases https://github.com/npm/rfcs/blob/main/implemented/0001-package-aliases.md
	if strings.HasPrefix(version, aliasPrefixPackageLockV1) {
		// this is an alias.
		// `"version": "npm:canonical-name@X.Y.Z"`
		canonicalPackageAndVersion := version[len(aliasPrefixPackageLockV1):]
		versionSeparator := strings.LastIndex(canonicalPackageAndVersion, "@")

		name = canonicalPackageAndVersion[:versionSeparator]
		version = canonicalPackageAndVersion[versionSeparator+1:]
	}

	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:         name,
			Version:      version,
			Locations:    source.NewLocationSet(location),
			PURL:         packageURL(name, version),
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: u.Resolved, Integrity: u.Integrity},
		},
	)
}

func newPackageLockV2Package(resolver source.FileResolver, location source.Location, name string, u lockPackage) pkg.Package {
	var licenses []string

	if u.License != nil {
		licenses = u.License
	}

	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:         name,
			Version:      u.Version,
			Locations:    source.NewLocationSet(location),
			PURL:         packageURL(name, u.Version),
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			Licenses:     internal.LogicalStrings{Simple: licenses},
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: u.Resolved, Integrity: u.Integrity},
		},
	)
}

func newPnpmPackage(resolver source.FileResolver, location source.Location, name, version string) pkg.Package {
	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:      name,
			Version:   version,
			Locations: source.NewLocationSet(location),
			PURL:      packageURL(name, version),
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	)
}

func newYarnLockPackage(resolver source.FileResolver, location source.Location, name, version string) pkg.Package {
	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:      name,
			Version:   version,
			Locations: source.NewLocationSet(location),
			PURL:      packageURL(name, version),
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	)
}

func finalizeLockPkg(resolver source.FileResolver, location source.Location, p pkg.Package) pkg.Package {
	p.Licenses.Simple = append(p.Licenses.Simple, addLicenses(p.Name, resolver, location)...)
	p.SetID()
	return p
}

func addLicenses(name string, resolver source.FileResolver, location source.Location) (allLicenses []string) {
	if resolver == nil {
		return allLicenses
	}
	dir := path.Dir(location.RealPath)
	pkgPath := []string{dir, "node_modules"}
	pkgPath = append(pkgPath, strings.Split(name, "/")...)
	pkgPath = append(pkgPath, "package.json")
	pkgFile := path.Join(pkgPath...)
	locations, err := resolver.FilesByPath(pkgFile)

	if err != nil {
		log.Debugf("an error occurred attempting to read: %s - %+v", pkgFile, err)
		return allLicenses
	}

	if len(locations) == 0 {
		return allLicenses
	}

	for _, l := range locations {
		contentReader, err := resolver.FileContentsByLocation(l)
		if err != nil {
			log.Debugf("error getting file content reader for %s: %v", pkgFile, err)
			return allLicenses
		}

		contents, err := io.ReadAll(contentReader)
		if err != nil {
			log.Debugf("error reading file contents for %s: %v", pkgFile, err)
			return allLicenses
		}

		var pkgJSON packageJSON
		err = json.Unmarshal(contents, &pkgJSON)
		if err != nil {
			log.Debugf("error parsing %s: %v", pkgFile, err)
			return allLicenses
		}

		licenses, err := pkgJSON.licensesFromJSON()
		if err != nil {
			log.Debugf("error getting licenses from %s: %v", pkgFile, err)
			return allLicenses
		}

		allLicenses = append(allLicenses, licenses...)
	}

	return allLicenses
}

// packageURL returns the PURL for the specific NPM package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string) string {
	var namespace string

	fields := strings.SplitN(name, "/", 2)
	if len(fields) > 1 {
		namespace = fields[0]
		name = fields[1]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeNPM,
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}
