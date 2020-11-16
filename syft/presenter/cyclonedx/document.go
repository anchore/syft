package cyclonedx

import (
	"encoding/xml"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
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

// NewDocument returns an empty CycloneDX Document object.
func NewDocument() Document {
	return Document{
		XMLNs:        "http://cyclonedx.org/schema/bom/1.2",
		XMLNsBd:      "http://cyclonedx.org/schema/ext/bom-descriptor/1.0",
		Version:      1,
		SerialNumber: uuid.New().URN(),
	}
}

// NewDocumentFromCatalog returns a CycloneDX Document object populated with the catalog contents.
func NewDocumentFromCatalog(catalog *pkg.Catalog, d distro.Distro) Document {
	bom := NewDocument()
	for p := range catalog.Enumerate() {
		component := Component{
			Type:       "library", // TODO: this is not accurate
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: p.PackageURL(d),
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
		bom.Components = append(bom.Components, component)
	}

	bom.BomDescriptor = NewBomDescriptor()

	return bom
}
