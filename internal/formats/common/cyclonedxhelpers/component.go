package cyclonedxhelpers

import (
	"reflect"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/formats/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func encodeComponent(p pkg.Package) cyclonedx.Component {
	props := encodeProperties(p, "syft:package")
	props = append(props, encodeCPEs(p)...)
	if len(p.Locations) > 0 {
		props = append(props, encodeProperties(p.Locations, "syft:location")...)
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
	}
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}

func decodeComponent(c *cyclonedx.Component) *pkg.Package {
	values := map[string]string{}
	for _, p := range *c.Properties {
		values[p.Name] = p.Value
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

	p.Metadata = decodePackageMetadata(values, c, p.MetadataType)

	if p.Type == "" {
		p.Type = pkg.TypeFromPURL(p.PURL)
	}

	return p
}

func decodeLocations(vals map[string]string) []source.Location {
	v := common.Decode(reflect.TypeOf([]source.Location{}), vals, "syft:location", CycloneDXFields)
	out, _ := v.([]source.Location)
	return out
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
