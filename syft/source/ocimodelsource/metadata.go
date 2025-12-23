package ocimodelsource

import "github.com/anchore/syft/syft/source"

// OCIModelMetadata represents all static metadata that defines what an OCI model artifact is.
type OCIModelMetadata struct {
	source.ImageMetadata
	Annotations map[string]string `json:"annotations,omitempty"`
}
