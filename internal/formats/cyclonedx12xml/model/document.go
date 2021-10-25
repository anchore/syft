package model

import (
	"encoding/xml"
)

// Source: https://github.com/CycloneDX/specification

// Document represents a CycloneDX BOM Document.
type Document struct {
	XMLName       xml.Name       `xml:"bom"`
	XMLNs         string         `xml:"xmlns,attr"`
	Version       int            `xml:"version,attr"`
	SerialNumber  string         `xml:"serialNumber,attr"`
	BomDescriptor *BomDescriptor `xml:"metadata"`             // The BOM descriptor extension
	Components    []Component    `xml:"components>component"` // The BOM contents
}
