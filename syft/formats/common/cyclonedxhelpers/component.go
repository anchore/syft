package cyclonedxhelpers

import (
	"reflect"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/formats/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func encodeComponent(p pkg.Package) cyclonedx.Component {
	props := encodeProperties(p, "syft:package")
	props = append(props, encodeCPEs(p)...)
	locations := p.Locations.ToSlice()
	if len(locations) > 0 {
		props = append(props, encodeProperties(locations, "syft:location")...)
	}
	if hasMetadata(p) {
		props = append(props, encodeProperties(p.Metadata, "syft:metadata")...)
	}

	var properties *[]cyclonedx.Property
	if len(props) > 0 {
		properties = &props
	}

	return cyclonedx.Component{
		Type:               cyclonedx.ComponentTypeLibrary,
		Name:               p.Name,
		Group:              encodeGroup(p),
		Version:            p.Version,
		PackageURL:         p.PURL,
		Licenses:           encodeLicenses(p),
		CPE:                encodeSingleCPE(p),
		Author:             encodeAuthor(p),
		Publisher:          encodePublisher(p),
		Description:        encodeDescription(p),
		ExternalReferences: encodeExternalReferences(p),
		Properties:         properties,
		BOMRef:             deriveBomRef(p),
	}
}

func deriveBomRef(p pkg.Package) string {
	// try and parse the PURL if possible and append syft id to it, to make
	// the purl unique in the BOM.
	// TODO: In the future we may want to dedupe by PURL and combine components with
	// the same PURL while preserving their unique metadata.
	if parsedPURL, err := packageurl.FromString(p.PURL); err == nil {
		parsedPURL.Qualifiers = append(parsedPURL.Qualifiers, packageurl.Qualifier{Key: "package-id", Value: string(p.ID())})
		return parsedPURL.ToString()
	}
	// fallback is to use strictly the ID if there is no valid pURL
	return string(p.ID())
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}

func decodeComponent(c *cyclonedx.Component) *pkg.Package {
	values := map[string]string{}
	if c.Properties != nil {
		for _, p := range *c.Properties {
			values[p.Name] = p.Value
		}
	}

	p := &pkg.Package{
		Name:      c.Name,
		Version:   c.Version,
		Locations: decodeLocations(values),
		Licenses:  decodeLicenses(c),
		CPEs:      decodeCPEs(c),
		PURL:      c.PackageURL,
	}

	common.DecodeInto(p, values, "syft:package", CycloneDXFields)

	p.MetadataType = pkg.CleanMetadataType(p.MetadataType)

	p.Metadata = decodePackageMetadata(values, c, p.MetadataType)

	if p.Type == "" {
		p.Type = pkg.TypeFromPURL(p.PURL)
	}

	if p.Language == "" {
		p.Language = pkg.LanguageFromPURL(p.PURL)
	}

	return p
}

func decodeLocations(vals map[string]string) source.LocationSet {
	v := common.Decode(reflect.TypeOf([]source.Location{}), vals, "syft:location", CycloneDXFields)
	out, ok := v.([]source.Location)
	if !ok {
		out = nil
	}
	return source.NewLocationSet(out...)
}

func decodePackageMetadata(vals map[string]string, c *cyclonedx.Component, typ pkg.MetadataType) interface{} {
	if typ != "" && c.Properties != nil {
		metaTyp, ok := pkg.MetadataTypeByName[typ]
		if !ok {
			return nil
		}
		metaPtrTyp := reflect.PtrTo(metaTyp)
		metaPtr := common.Decode(metaPtrTyp, vals, "syft:metadata", CycloneDXFields)

		// Map all explicit metadata properties
		decodeAuthor(c.Author, metaPtr)
		decodeGroup(c.Group, metaPtr)
		decodePublisher(c.Publisher, metaPtr)
		decodeDescription(c.Description, metaPtr)
		decodeExternalReferences(c, metaPtr)

		// return the actual interface{} -> struct ... not interface{} -> *struct
		return common.PtrToStruct(metaPtr)
	}

	return nil
}
