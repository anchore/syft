package cyclonedx

import (
	"encoding/xml"

	"github.com/anchore/syft/syft/pkg"
	"github.com/google/uuid"
)

// Source: https://github.com/CycloneDX/specification

type Document struct {
	XMLName       xml.Name    `xml:"bom"`
	XMLNs         string      `xml:"xmlns,attr"`
	Version       int         `xml:"version,attr"`
	SerialNumber  string      `xml:"serialNumber,attr"`
	Components    []Component `xml:"components>component"` // The BOM contents
	BomDescriptor *BdMetadata `xml:"bd:metadata"`          // The BOM descriptor extension
}

func NewDocument() Document {
	return Document{
		XMLNs:        "http://cyclonedx.org/schema/bom/1.2",
		Version:      1,
		SerialNumber: uuid.New().URN(),
	}
}

func NewDocumentFromCatalog(catalog *pkg.Catalog) Document {
	bom := NewDocument()
	for p := range catalog.Enumerate() {
		component := Component{
			Type:    "library", // TODO: this is not accurate
			Name:    p.Name,
			Version: p.Version,
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
