package filesource

import "github.com/anchore/syft/syft/file"

type Metadata struct {
	Path     string        `json:"path" yaml:"path"`
	Digests  []file.Digest `json:"digests,omitempty" yaml:"digests,omitempty"`
	MIMEType string        `json:"mimeType" yaml:"mimeType"`
}
