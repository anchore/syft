package pkg

import "github.com/anchore/syft/syft/sort"

// ElixirMixLockEntry is a struct that represents a single entry in a mix.lock file
type ElixirMixLockEntry struct {
	Name       string `mapstructure:"name" json:"name"`
	Version    string `mapstructure:"version" json:"version"`
	PkgHash    string `mapstructure:"pkgHash" json:"pkgHash"`
	PkgHashExt string `mapstructure:"pkgHashExt" json:"pkgHashExt"`
}

func (m ElixirMixLockEntry) Compare(other ElixirMixLockEntry) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.PkgHash, other.PkgHash); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.PkgHashExt, other.PkgHashExt); i != 0 {
		return i
	}
	return 0
}

func (m ElixirMixLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(ElixirMixLockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
