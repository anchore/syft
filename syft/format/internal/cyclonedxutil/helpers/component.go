package helpers

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/pkg"
)

func EncodeComponent(p pkg.Package, supplier string, locationSorter func(a, b file.Location) int) cyclonedx.Component {
	props := EncodeProperties(p, "syft:package")

	if p.Metadata != nil {
		// encode the metadataType as a property, something that doesn't exist on the core model
		props = append(props, cyclonedx.Property{
			Name:  "syft:package:metadataType",
			Value: packagemetadata.JSONName(p.Metadata),
		})
	}

	props = append(props, encodeCPEs(p)...)
	locations := p.Locations.ToSlice(locationSorter)
	if len(locations) > 0 {
		props = append(props, EncodeProperties(locations, "syft:location")...)
	}
	if hasMetadata(p) {
		props = append(props, EncodeProperties(p.Metadata, "syft:metadata")...)
	}

	var properties *[]cyclonedx.Property
	if len(props) > 0 {
		properties = &props
	}

	componentType := cyclonedx.ComponentTypeLibrary
	if p.Type == pkg.BinaryPkg {
		componentType = cyclonedx.ComponentTypeApplication
	}

	return cyclonedx.Component{
		Type:               componentType,
		Name:               p.Name,
		Group:              encodeGroup(p),
		Version:            p.Version,
		Supplier:           encodeSupplier(p, supplier),
		PackageURL:         p.PURL,
		Licenses:           encodeLicenses(p),
		CPE:                encodeSingleCPE(p),
		Author:             encodeAuthor(p),
		Publisher:          encodePublisher(p),
		Description:        encodeDescription(p),
		ExternalReferences: encodeExternalReferences(p),
		Properties:         properties,
		BOMRef:             DeriveBomRef(p),
	}
}

// TODO: we eventually want to update this so that we can read "supplier" from different syft metadata
func encodeSupplier(_ pkg.Package, sbomSupplier string) *cyclonedx.OrganizationalEntity {
	if sbomSupplier != "" {
		return &cyclonedx.OrganizationalEntity{
			Name: sbomSupplier,
		}
	}
	return nil
}

func DeriveBomRef(p pkg.Package) string {
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
		Version:   c.Version,
		Locations: decodeLocations(values),
		Licenses:  pkg.NewLicenseSet(decodeLicenses(c)...),
		CPEs:      decodeCPEs(c),
	}

	// note: this may write in syft package type information
	DecodeInto(p, values, "syft:package", CycloneDXFields)

	metadataType := values["syft:package:metadataType"]

	p.Metadata = decodePackageMetadata(values, c, metadataType)

	// this will either use the purl from the component or generate a new one based off of any type information
	// that was decoded above.
	p.PURL = getPURL(c, p.Type)

	if p.Type == "" {
		p.Type = pkg.TypeFromPURL(p.PURL)
	}

	setPackageName(p, c)

	internal.Backfill(p)
	p.SetID()

	return p
}

func getPURL(c *cyclonedx.Component, ty pkg.Type) string {
	if c.PackageURL != "" {
		// if there is a purl that where the namespace does not match the group information, we may
		// accidentally drop group. We should consider adding group as a top-level syft package field.
		return c.PackageURL
	}

	if strings.HasPrefix(c.BOMRef, "pkg:") {
		// the bomref is a purl, so try to use that as the purl
		_, err := packageurl.FromString(c.BOMRef)
		if err == nil {
			return c.BOMRef
		}
	}

	if ty == "" {
		return ""
	}

	tyStr := ty.PackageURLType()
	switch tyStr {
	case "", packageurl.TypeGeneric:
		return ""
	}

	purl := packageurl.PackageURL{
		Type:      tyStr,
		Namespace: c.Group,
		Name:      c.Name,
		Version:   c.Version,
	}

	return purl.ToString()
}

func setPackageName(p *pkg.Package, c *cyclonedx.Component) {
	name := c.Name
	if c.Group != "" {
		switch p.Type {
		case pkg.JavaPkg:
			if p.Metadata == nil {
				p.Metadata = pkg.JavaArchive{}
			}
			var pomProperties *pkg.JavaPomProperties
			javaMetadata, ok := p.Metadata.(pkg.JavaArchive)
			if ok {
				pomProperties = javaMetadata.PomProperties
				if pomProperties == nil {
					pomProperties = &pkg.JavaPomProperties{}
					javaMetadata.PomProperties = pomProperties
					p.Metadata = javaMetadata
				}
			}
			if pomProperties != nil {
				if pomProperties.ArtifactID == "" {
					pomProperties.ArtifactID = c.Name
				}
				if pomProperties.GroupID == "" {
					pomProperties.GroupID = c.Group
				}
				if pomProperties.Version == "" {
					pomProperties.Version = p.Version
				}
			}
		default:
			name = fmt.Sprintf("%s/%s", c.Group, name)
		}
	}
	p.Name = name
}

func decodeLocations(vals map[string]string) file.LocationSet {
	v := Decode(reflect.TypeOf([]file.Location{}), vals, "syft:location", CycloneDXFields)
	out, ok := v.([]file.Location)
	if !ok {
		out = nil
	}
	return file.NewLocationSet(out...)
}

func decodePackageMetadata(vals map[string]string, c *cyclonedx.Component, typeName string) interface{} {
	if typeName != "" && c.Properties != nil {
		metadataType := packagemetadata.ReflectTypeFromJSONName(typeName)
		if metadataType == nil {
			return nil
		}
		metaPtrTyp := reflect.PointerTo(metadataType)
		metaPtr := Decode(metaPtrTyp, vals, "syft:metadata", CycloneDXFields)

		// Map all explicit metadata properties
		decodeAuthor(c.Author, metaPtr)
		decodeGroup(c.Group, metaPtr)
		decodePublisher(c.Publisher, metaPtr)
		decodeDescription(c.Description, metaPtr)
		decodeExternalReferences(c, metaPtr)

		// return the actual interface{} -> struct ... not interface{} -> *struct
		return PtrToStruct(metaPtr)
	}

	return nil
}
