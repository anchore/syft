package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func encodeComponent(p pkg.Package) cyclonedx.Component {
	return cyclonedx.Component{
		Type:               cyclonedx.ComponentTypeLibrary,
		Name:               p.Name,
		Group:              encodeGroup(p),
		Version:            p.Version,
		PackageURL:         p.PURL,
		Licenses:           encodeLicenses(p),
		CPE:                encodeCPE(p),
		Author:             encodeAuthor(p),
		Publisher:          encodePublisher(p),
		Description:        encodeDescription(p),
		ExternalReferences: encodeExternalReferences(p),
		Properties:         encodeProperties(p),
	}
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}

func decodeComponent(c *cyclonedx.Component) *pkg.Package {
	typ := pkg.Type(prop(c, "type"))
	purl := c.PackageURL
	if typ == "" && purl != "" {
		typ = pkg.TypeFromPURL(purl)
	}

	metaType, meta := decodePackageMetadata(c)

	p := &pkg.Package{
		Name:         c.Name,
		Version:      c.Version,
		FoundBy:      prop(c, "foundBy"),
		Locations:    nil,
		Licenses:     decodeLicenses(c),
		Language:     pkg.Language(prop(c, "language")),
		Type:         typ,
		CPEs:         decodeCPEs(c),
		PURL:         purl,
		MetadataType: metaType,
		Metadata:     meta,
	}

	return p
}

func decodePackageMetadata(c *cyclonedx.Component) (pkg.MetadataType, interface{}) {
	if c.Properties != nil {
		typ := prop(c, "metadataType")
		if typ != "" {
			switch typ {
			case "ApkMetadata":
				return pkg.ApkMetadataType, pkg.ApkMetadata{
					Package:          prop(c, "package"),
					OriginPackage:    prop(c, "originPackage"),
					Maintainer:       prop(c, "maintainer"),
					Version:          prop(c, "version"),
					License:          prop(c, "license"),
					Architecture:     prop(c, "architecture"),
					URL:              prop(c, "url"),
					Description:      prop(c, "description"),
					Size:             propInt(c, "size"),
					InstalledSize:    propInt(c, "installedSize"),
					PullDependencies: prop(c, "pullDependencies"),
					PullChecksum:     prop(c, "pullChecksum"),
					GitCommitOfAport: prop(c, "gitCommitOfAport"),
					Files:            []pkg.ApkFileRecord{},
				}
			case "DpkgMetadata":
				return pkg.DpkgMetadataType, pkg.DpkgMetadata{
					Package:       prop(c, "package"),
					Source:        prop(c, "source"),
					Version:       prop(c, "version"),
					SourceVersion: prop(c, "sourceVersion"),
					Architecture:  prop(c, "architecture"),
					Maintainer:    prop(c, "maintainer"),
					InstalledSize: propInt(c, "installedSize"),
					Files:         []pkg.DpkgFileRecord{},
				}
			case "RpmdbMetadata":
				return pkg.RpmdbMetadataType, pkg.RpmdbMetadata{
					Name:      prop(c, "name"),
					Version:   prop(c, "version"),
					Epoch:     propIntNil(c, "epoch"),
					Arch:      prop(c, "arch"),
					Release:   prop(c, "release"),
					SourceRpm: prop(c, "sourceRpm"),
					Size:      propInt(c, "size"),
					License:   prop(c, "license"),
					Vendor:    prop(c, "vendor"),
					Files:     []pkg.RpmdbFileRecord{},
				}
			}
		}
	}

	return pkg.UnknownMetadataType, nil
}
