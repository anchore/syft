package kernel

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const linuxKernelPackageName = "linux-kernel"

func newLinuxKernelPackage(metadata pkg.LinuxKernelMetadata, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         linuxKernelPackageName,
		Version:      metadata.Version,
		Locations:    source.NewLocationSet(locations...),
		PURL:         packageURL(linuxKernelPackageName, metadata.Version),
		Type:         pkg.LinuxKernelPkg,
		MetadataType: pkg.LinuxKernelMetadataType,
		Metadata:     metadata,
	}

	p.SetID()

	return p
}

func newLinuxKernelModulePackage(metadata pkg.LinuxKernelModuleMetadata, locations ...source.Location) pkg.Package {
	licenses := make([]pkg.License, 0)
	if metadata.License != "" {
		licenses = append(licenses, pkg.License{
			Value: metadata.License,
			Type:  license.Declared,
		})
	}

	p := pkg.Package{
		Name:         metadata.Name,
		Version:      metadata.Version,
		Locations:    source.NewLocationSet(locations...),
		Licenses:     licenses,
		PURL:         packageURL(metadata.Name, metadata.Version),
		Type:         pkg.LinuxKernelModulePkg,
		MetadataType: pkg.LinuxKernelModuleMetadataType,
		Metadata:     metadata,
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific Kernel package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string) string {
	var namespace string

	fields := strings.SplitN(name, "/", 2)
	if len(fields) > 1 {
		namespace = fields[0]
		name = fields[1]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}
