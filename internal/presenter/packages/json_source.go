package packages

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

// JSONSource object represents the thing that was cataloged
type JSONSource struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

type JSONImageSource struct {
	source.ImageMetadata
	Scope source.Scope `json:"scope"`
}

// NewJSONSource creates a new source object to be represented into JSON.
func NewJSONSource(src source.Metadata, scope source.Scope) (JSONSource, error) {
	switch src.Scheme {
	case source.ImageScheme:
		return JSONSource{
			Type: "image",
			Target: JSONImageSource{
				Scope:         scope,
				ImageMetadata: src.ImageMetadata,
			},
		}, nil
	case source.DirectoryScheme:
		return JSONSource{
			Type:   "directory",
			Target: src.Path,
		}, nil
	default:
		return JSONSource{}, fmt.Errorf("unsupported source: %q", src.Scheme)
	}
}
