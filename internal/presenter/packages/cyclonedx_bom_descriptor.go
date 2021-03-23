package packages

import (
	"encoding/xml"
	"time"

	"github.com/anchore/syft/syft/source"
)

// Source: https://cyclonedx.org/ext/bom-descriptor/

// CycloneDxBomDescriptor represents all metadata surrounding the BOM report (such as when the BOM was made, with which tool, and the item being cataloged).
type CycloneDxBomDescriptor struct {
	XMLName   xml.Name              `xml:"metadata"`
	Timestamp string                `xml:"timestamp,omitempty"` // The date and time (timestamp) when the document was created
	Tools     []CycloneDxBdTool     `xml:"tools>tool"`          // The tool used to create the BOM.
	Component *CycloneDxBdComponent `xml:"component"`           // The component that the BOM describes.
}

// CycloneDxBdTool represents the tool that created the BOM report.
type CycloneDxBdTool struct {
	XMLName xml.Name `xml:"tool"`
	Vendor  string   `xml:"vendor,omitempty"`  // The vendor of the tool used to create the BOM.
	Name    string   `xml:"name,omitempty"`    // The name of the tool used to create the BOM.
	Version string   `xml:"version,omitempty"` // The version of the tool used to create the BOM.
	// TODO: hashes, author, manufacture, supplier
	// TODO: add user-defined fields for the remaining build/version parameters
}

// CycloneDxBdComponent represents the software/package being cataloged.
type CycloneDxBdComponent struct {
	XMLName xml.Name `xml:"component"`
	CycloneDxComponent
}

// NewCycloneDxBomDescriptor returns a new CycloneDxBomDescriptor tailored for the current time and "syft" tool details.
func NewCycloneDxBomDescriptor(name, version string, srcMetadata source.Metadata) *CycloneDxBomDescriptor {
	descriptor := CycloneDxBomDescriptor{
		XMLName:   xml.Name{},
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: []CycloneDxBdTool{
			{
				Vendor:  "anchore",
				Name:    name,
				Version: version,
			},
		},
	}

	switch srcMetadata.Scheme {
	case source.ImageScheme:
		descriptor.Component = &CycloneDxBdComponent{
			CycloneDxComponent: CycloneDxComponent{
				Type:    "container",
				Name:    srcMetadata.ImageMetadata.UserInput,
				Version: srcMetadata.ImageMetadata.ManifestDigest,
			},
		}
	case source.DirectoryScheme:
		descriptor.Component = &CycloneDxBdComponent{
			CycloneDxComponent: CycloneDxComponent{
				Type: "file",
				Name: srcMetadata.Path,
			},
		}
	}

	return &descriptor
}
