package model

import (
	"encoding/xml"
)

// Source: https://cyclonedx.org/ext/bom-descriptor/

// BomDescriptor represents all metadata surrounding the BOM report (such as when the BOM was made, with which tool, and the item being cataloged).
type BomDescriptor struct {
	XMLName   xml.Name                `xml:"metadata"`
	Timestamp string                  `xml:"timestamp,omitempty"` // The date and time (timestamp) when the document was created
	Tools     []BomDescriptorTool     `xml:"tools>tool"`          // The tool used to create the BOM.
	Component *BomDescriptorComponent `xml:"component"`           // The component that the BOM describes.
}

// BomDescriptorTool represents the tool that created the BOM report.
type BomDescriptorTool struct {
	XMLName xml.Name `xml:"tool"`
	Vendor  string   `xml:"vendor,omitempty"`  // The vendor of the tool used to create the BOM.
	Name    string   `xml:"name,omitempty"`    // The name of the tool used to create the BOM.
	Version string   `xml:"version,omitempty"` // The version of the tool used to create the BOM.
	// TODO: hashes, author, manufacture, supplier
	// TODO: add user-defined fields for the remaining build/version parameters
}

// BomDescriptorComponent represents the software/package being cataloged.
type BomDescriptorComponent struct {
	XMLName xml.Name `xml:"component"`
	Component
}
