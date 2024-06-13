package source

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sort"
)

type FileMetadata struct {
	Path     string        `json:"path" yaml:"path"`
	Digests  []file.Digest `json:"digests,omitempty" yaml:"digests,omitempty"`
	MIMEType string        `json:"mimeType" yaml:"mimeType"`
}

func (fm FileMetadata) Compare(other FileMetadata) int {
	if i := sort.CompareOrd(fm.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.CompareArrays(fm.Digests, other.Digests); i != 0 {
		return i
	}
	if i := sort.CompareOrd(fm.MIMEType, other.MIMEType); i != 0 {
		return i
	}
	return 0
}

func (fm FileMetadata) TryCompare(other any) (bool, int) {
	if other, exists := other.(FileMetadata); exists {
		return true, fm.Compare(other)
	}
	return false, 0
}
