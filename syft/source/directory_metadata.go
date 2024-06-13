package source

import "github.com/anchore/syft/syft/sort"

type DirectoryMetadata struct {
	Path string `json:"path" yaml:"path"`
	Base string `json:"-" yaml:"-"` // though this is important, for display purposes it leaks too much information (abs paths)
}

func (dm DirectoryMetadata) Compare(other DirectoryMetadata) int {
	if i := sort.CompareOrd(dm.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.CompareOrd(dm.Base, other.Base); i != 0 {
		return i
	}
	return 0
}

func (dm DirectoryMetadata) TryCompare(other any) (bool, int) {
	if other, exists := other.(DirectoryMetadata); exists {
		return true, dm.Compare(other)
	}
	return false, 0
}
