package cyclonedx

import (
	"encoding/xml"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

// Source: https://github.com/CycloneDX/specification

// Document represents a CycloneDX BOM Document.
type Document struct {
	XMLName       xml.Name       `xml:"bom"`
	XMLNs         string         `xml:"xmlns,attr"`
	XMLNsBd       string         `xml:"xmlns:bd,attr"`
	Version       int            `xml:"version,attr"`
	SerialNumber  string         `xml:"serialNumber,attr"`
	Components    []Component    `xml:"components>component"` // The BOM contents
	BomDescriptor *BomDescriptor `xml:"bd:metadata"`          // The BOM descriptor extension
}

// NewDocumentFromCatalog returns a CycloneDX Document object populated with the catalog contents.
func NewDocument(catalog *pkg.Catalog, srcMetadata source.Metadata) Document {
	versionInfo := version.FromBuild()

	doc := Document{
		XMLNs:         "http://cyclonedx.org/schema/bom/1.2",
		XMLNsBd:       "http://cyclonedx.org/schema/ext/bom-descriptor/1.0",
		Version:       1,
		SerialNumber:  uuid.New().URN(),
		BomDescriptor: NewBomDescriptor(internal.ApplicationName, versionInfo.Version, srcMetadata),
	}

	// attach components
	for p := range catalog.Enumerate() {
		component := Component{
			Type:       "library", // TODO: this is not accurate
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: p.PURL,
		}
		var licenses []License
		for _, licenseName := range p.Licenses {
			licenses = append(licenses, License{
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
