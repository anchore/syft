package ocimodelsource

import "github.com/anchore/syft/syft/source"

// OCIModelMetadata represents all static metadata that defines what an OCI model artifact is.
// The struct tag for Annotations with id:"-" is used so that we do not generate different source ID based
// on changes to the annotations of a source image. This does not constitute a different identifiable.
type OCIModelMetadata struct {
	source.ImageMetadata `json:",inline"`
	Annotations          map[string]string `json:"annotations,omitempty" id:"-"`
}
