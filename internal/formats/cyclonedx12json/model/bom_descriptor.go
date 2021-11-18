package model

// Source: https://cyclonedx.org/ext/bom-descriptor/

// BomDescriptor represents all metadata surrounding the BOM report (such as when the BOM was made, with which tool, and the item being cataloged).
type BomDescriptor struct {
	Timestamp string                  `json:"timestamp,omitempty"` // The date and time (timestamp) when the document was created
	Tools     []BomDescriptorTool     `json:"tools"`               // The tool used to create the BOM.
	Component *BomDescriptorComponent `json:"component"`           // The component that the BOM describes.
}

// BomDescriptorTool represents the tool that created the BOM report.
type BomDescriptorTool struct {
	Vendor  string `json:"vendor,omitempty"`  // The vendor of the tool used to create the BOM.
	Name    string `json:"name,omitempty"`    // The name of the tool used to create the BOM.
	Version string `json:"version,omitempty"` // The version of the tool used to create the BOM.
	// TODO: hashes, author, manufacture, supplier
	// TODO: add user-defined fields for the remaining build/version parameters
}

// BomDescriptorComponent represents the software/package being cataloged.
type BomDescriptorComponent struct {
	Component
}
