package cyclonedx

import (
	"encoding/xml"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
)

// Source: https://cyclonedx.org/ext/bom-descriptor/

// BomDescriptor represents all metadata surrounding the BOM report (such as when the BOM was made, with which tool, and the item being cataloged).
type BomDescriptor struct {
	XMLName   xml.Name     `xml:"bd:metadata"`
	Timestamp string       `xml:"bd:timestamp,omitempty"` // The date and time (timestamp) when the document was created
	Tool      *BdTool      `xml:"bd:tool"`                // The tool used to create the BOM.
	Component *BdComponent `xml:"bd:component"`           // The component that the BOM describes.
}

// BdTool represents the tool that created the BOM report.
type BdTool struct {
	XMLName xml.Name `xml:"bd:tool"`
	Vendor  string   `xml:"bd:vendor,omitempty"`  // The vendor of the tool used to create the BOM.
	Name    string   `xml:"bd:name,omitempty"`    // The name of the tool used to create the BOM.
	Version string   `xml:"bd:version,omitempty"` // The version of the tool used to create the BOM.
	// TODO: hashes, author, manufacture, supplier
	// TODO: add user-defined fields for the remaining build/version parameters
}

// BdComponent represents the software/package being cataloged.
type BdComponent struct {
	XMLName xml.Name `xml:"bd:component"`
	Component
}

// NewBomDescriptor returns a new BomDescriptor tailored for the current time and "syft" tool details.
func NewBomDescriptor() *BomDescriptor {
	versionInfo := version.FromBuild()
	return &BomDescriptor{
		XMLName:   xml.Name{},
		Timestamp: time.Now().Format(time.RFC3339),
		Tool: &BdTool{
			Vendor:  "anchore",
			Name:    internal.ApplicationName,
			Version: versionInfo.Version,
		},
	}
}
