package static_binary

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func (c *staticBinaryCataloger) newStaticBinaryPackage(resolver file.Resolver, libs []string, notes []byte, location file.Location) pkg.Package {

	//Create and set a var to access our metadata
	var metadata pkg.StaticBinaryPackageMetadata
	newerr := json.Unmarshal(notes, &metadata)
	if newerr != nil {
		fmt.Println("Something bad happened again:")
	}
	//Get an array of licenses
	licenses, err := c.licenses.getLicenses(resolver, metadata.Name, location.VirtualPath)
	if err != nil {
		log.Tracef("error getting licenses for static binary package: %s %v", metadata.Name, err)
	}

	//Construct the package

	p := pkg.Package{
		Name:         metadata.Name,
		Version:      metadata.Version,
		Licenses:     pkg.NewLicenseSet(licenses...),
		PURL:         packageURL(metadata.Name, metadata.Version),
		Language:     pkg.StaticBinary,
		Type:         pkg.StaticBinaryPkg,
		Locations:    file.NewLocationSet(location),
		MetadataType: pkg.StaticBinaryPackageMetadataType,
		Metadata:     pkg.StaticBinaryPackageMetadata{},
	}

	p.SetID()

	return p

}
func (c *staticBinaryLibCataloger) newStaticBinaryLibPackage(resolver file.Resolver, libs []string, notes []byte, location file.Location) pkg.Package {
	//Create and set a var to access our metadata
	var metadata pkg.StaticBinaryLibraryMetadata
	newerr := json.Unmarshal(notes, &metadata)
	if newerr != nil {
		fmt.Println("Something bad happened again:")
	}
	//Get an array of licenses
	licenses, err := c.licenses.getLicenses(resolver, metadata.Name, location.VirtualPath)
	if err != nil {
		log.Tracef("error getting licenses for static binary package: %s %v", metadata.Name, err)
	}

	//Construct the package

	p := pkg.Package{
		Name:         metadata.Name,
		Version:      metadata.Version,
		Licenses:     pkg.NewLicenseSet(licenses...),
		PURL:         packageURL(metadata.Name, metadata.Version),
		Language:     pkg.StaticBinary,
		Type:         pkg.StaticLibraryPkg,
		Locations:    file.NewLocationSet(location),
		MetadataType: pkg.StaticBinaryLibraryMetadataType,
		Metadata:     pkg.StaticBinaryLibraryMetadata{},
	}

	p.SetID()

	return p

}
func (c *staticBinaryCataloger) newStaticBinaryLibPackage(resolver file.Resolver, lib string, notes []byte, location file.Location) pkg.Package {

	//Create and set a var to access our metadata
	var metadata pkg.StaticBinaryPackageMetadata
	newerr := json.Unmarshal(notes, &metadata)
	if newerr != nil {
		fmt.Println("Something bad happened again:")
	}
	//Get an array of licenses
	//This should include licenses for 3rd party libs at this stage
	licenses, err := c.licenses.getLicenses(resolver, metadata.Name, location.VirtualPath)
	if err != nil {
		log.Tracef("error getting licenses for static binary package: %s %v", metadata.Name, err)
	}

	//Construct the package

	p := pkg.Package{
		Name:         lib,
		Version:      metadata.Version,
		Licenses:     pkg.NewLicenseSet(licenses...),
		PURL:         packageURL(metadata.Name, metadata.Version),
		Language:     pkg.StaticBinary,
		Type:         pkg.StaticLibraryPkg,
		Locations:    file.NewLocationSet(location),
		MetadataType: pkg.StaticBinaryLibraryMetadataType,
		Metadata:     pkg.StaticBinaryLibraryMetadata{},
	}

	p.SetID()

	return p

}
func (c *staticBinaryLibCataloger) newStaticLibraryLibPackage(resolver file.Resolver, lib string, notes []byte, location file.Location) pkg.Package {

	//Create and set a var to access our metadata
	var metadata pkg.StaticBinaryPackageMetadata
	newerr := json.Unmarshal(notes, &metadata)
	if newerr != nil {
		fmt.Println("Something bad happened again:")
	}
	//Get an array of licenses
	//This should include licenses for 3rd party libs at this stage
	licenses, err := c.licenses.getLicenses(resolver, metadata.Name, location.VirtualPath)
	if err != nil {
		log.Tracef("error getting licenses for static binary package: %s %v", metadata.Name, err)
	}

	//Construct the package

	p := pkg.Package{
		Name:         lib,
		Version:      metadata.Version,
		Licenses:     pkg.NewLicenseSet(licenses...),
		PURL:         packageURL(metadata.Name, metadata.Version),
		Language:     pkg.StaticBinary,
		Type:         pkg.StaticLibraryPkg,
		Locations:    file.NewLocationSet(location),
		MetadataType: pkg.StaticBinaryLibraryMetadataType,
		Metadata:     pkg.StaticBinaryLibraryMetadata{},
	}

	p.SetID()

	return p

}

func packageURL(name string, version string) string {
	var namespace = "momentum"
	return packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}
