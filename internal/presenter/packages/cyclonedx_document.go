package packages

import (
	"encoding/xml"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

// Source: https://github.com/CycloneDX/specification

// CycloneDxDocument represents a CycloneDX BOM CycloneDxDocument.
type CycloneDxDocument struct {
	XMLName       xml.Name                `xml:"bom"`
	XMLNs         string                  `xml:"xmlns,attr"`
	Version       int                     `xml:"version,attr"`
	SerialNumber  string                  `xml:"serialNumber,attr"`
	BomDescriptor *CycloneDxBomDescriptor `xml:"metadata"`             // The BOM descriptor extension
	Components    []CycloneDxComponent    `xml:"components>component"` // The BOM contents
}

// NewCycloneDxDocument returns a CycloneDX CycloneDxDocument object populated with the catalog contents.
func NewCycloneDxDocument(catalog *pkg.Catalog, srcMetadata source.Metadata) CycloneDxDocument {
	versionInfo := version.FromBuild()

	doc := CycloneDxDocument{
		XMLNs:         "http://cyclonedx.org/schema/bom/1.2",
		Version:       1,
		SerialNumber:  uuid.New().URN(),
		BomDescriptor: NewCycloneDxBomDescriptor(internal.ApplicationName, versionInfo.Version, srcMetadata),
	}

	// attach components
	for p := range catalog.Enumerate() {
		component := CycloneDxComponent{
			Type:       "library", // TODO: this is not accurate
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: p.PURL,
		}
		var licenses []CycloneDxLicense
		for _, licenseName := range p.Licenses {
			licenses = append(licenses, CycloneDxLicense{
				Name: licenseName,
			})
		}
		if len(licenses) > 0 {
			component.Licenses = &licenses
		}
		doc.Components = append(doc.Components, component)
	}

	return doc
}
