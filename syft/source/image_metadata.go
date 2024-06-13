package source

import "github.com/anchore/syft/syft/sort"

// ImageMetadata represents all static metadata that defines what a container image is. This is useful to later describe
// "what" was cataloged without needing the more complicated stereoscope Image objects or FileResolver objects.
type ImageMetadata struct {
	UserInput      string            `json:"userInput"`
	ID             string            `json:"imageID"`
	ManifestDigest string            `json:"manifestDigest"`
	MediaType      string            `json:"mediaType"`
	Tags           []string          `json:"tags"`
	Size           int64             `json:"imageSize"`
	Layers         []LayerMetadata   `json:"layers"`
	RawManifest    []byte            `json:"manifest"`
	RawConfig      []byte            `json:"config"`
	RepoDigests    []string          `json:"repoDigests"`
	Architecture   string            `json:"architecture"`
	Variant        string            `json:"architectureVariant,omitempty"`
	OS             string            `json:"os"`
	Labels         map[string]string `json:"labels,omitempty"`
}

// LayerMetadata represents all static metadata that defines what a container image layer is.
type LayerMetadata struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func (lm LayerMetadata) Compare(other LayerMetadata) int {
	if i := sort.CompareOrd(lm.MediaType, other.MediaType); i != 0 {
		return i
	}
	if i := sort.CompareOrd(lm.Digest, other.Digest); i != 0 {
		return i
	}
	if i := sort.CompareOrd(lm.Size, other.Size); i != 0 {
		return i
	}
	return 0
}
func (im ImageMetadata) Compare(other ImageMetadata) int {
	if i := sort.CompareOrd(im.UserInput, other.UserInput); i != 0 {
		return i
	}
	if i := sort.CompareOrd(im.ID, other.ID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(im.ManifestDigest, other.ManifestDigest); i != 0 {
		return i
	}
	if i := sort.CompareOrd(im.MediaType, other.MediaType); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(im.Tags, other.Tags); i != 0 {
		return i
	}
	if i := sort.CompareOrd(im.Size, other.Size); i != 0 {
		return i
	}
	if i := sort.CompareArrays(im.Layers, other.Layers); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(im.RawManifest, other.RawManifest); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(im.RawConfig, other.RawConfig); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(im.RepoDigests, other.RepoDigests); i != 0 {
		return i
	}
	if i := sort.CompareOrd(im.Architecture, other.Architecture); i != 0 {
		return i
	}
	if i := sort.CompareOrd(im.Variant, other.Variant); i != 0 {
		return i
	}
	if i := sort.CompareOrd(im.OS, other.OS); i != 0 {
		return i
	}
	if i := sort.CompareMapOrd(im.Labels, other.Labels); i != 0 {
		return i
	}
	return 0
}

func (im ImageMetadata) TryCompare(other any) (bool, int) {
	if other, exists := other.(ImageMetadata); exists {
		return true, im.Compare(other)
	}
	return false, 0
}
