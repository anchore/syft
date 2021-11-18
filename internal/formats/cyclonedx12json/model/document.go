package model

// Source: https://github.com/CycloneDX/specification

// Document represents a CycloneDX BOM Document.
type Document struct {
	Version       int            `json:"version"`
	SerialNumber  string         `json:"serialNumber"`
	BomDescriptor *BomDescriptor `json:"metadata"`   // The BOM descriptor extension
	Components    []Component    `json:"components"` // The BOM contents
}
