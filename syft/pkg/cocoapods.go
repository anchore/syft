package pkg

import "github.com/anchore/syft/syft/sort"

// CocoaPodfileLockEntry represents a single entry from the "Pods" section of a Podfile.lock file.
type CocoaPodfileLockEntry struct {
	Checksum string `mapstructure:"checksum" json:"checksum"`
}

func (m CocoaPodfileLockEntry) Compare(other CocoaPodfileLockEntry) int {
	if i := sort.CompareOrd(m.Checksum, other.Checksum); i != 0 {
		return i
	}
	return 0
}

func (m CocoaPodfileLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(CocoaPodfileLockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
