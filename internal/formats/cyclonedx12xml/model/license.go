package model

import "encoding/xml"

// License represents a single software license for a Component
type License struct {
	XMLName xml.Name `xml:"license"`
	ID      string   `xml:"id,omitempty"`   // A valid SPDX license ID
	Name    string   `xml:"name,omitempty"` // If SPDX does not define the license used, this field may be used to provide the license name
}
