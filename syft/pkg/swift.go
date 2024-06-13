package pkg

import "github.com/anchore/syft/syft/sort"

type SwiftPackageManagerResolvedEntry struct {
	Revision string `mapstructure:"revision" json:"revision"`
}

func (m SwiftPackageManagerResolvedEntry) Compare(other SwiftPackageManagerResolvedEntry) int {
	if i := sort.CompareOrd(m.Revision, other.Revision); i != 0 {
		return i
	}
	return 0
}

func (m SwiftPackageManagerResolvedEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(SwiftPackageManagerResolvedEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
