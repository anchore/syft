package cyclonedx

import (
	"encoding/xml"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
)

// Source: https://cyclonedx.org/ext/bom-descriptor/

type BdMetadata struct {
	XMLName   xml.Name     `xml:"bd:metadata"`
	Timestamp string       `xml:"bd:timestamp,omitempty"`
	Tool      *BdTool      `xml:"bd:tool"`
	Component *BdComponent `xml:"bd:component"`
}

type BdTool struct {
	XMLName xml.Name `xml:"bd:tool"`
	Vendor  string   `xml:"bd:vendor,omitempty"`
	Name    string   `xml:"bd:name,omitempty"`
	Version string   `xml:"bd:version,omitempty"`
	// TODO: hashes, author, manufacture, supplier
}

type BdComponent struct {
	XMLName xml.Name `xml:"bd:component"`
	Component
}

func NewBomDescriptor() *BdMetadata {
	versionInfo := version.FromBuild()
	return &BdMetadata{
		XMLName:   xml.Name{},
		Timestamp: time.Now().Format(time.RFC3339),
		Tool: &BdTool{
			Vendor:  "anchore",
			Name:    internal.ApplicationName,
			Version: versionInfo.Version,
		},
	}
}
