package pkg

import "github.com/anchore/syft/syft/sort"

// ErlangRebarLockEntry represents a single package entry from the "deps" section within an Erlang rebar.lock file.
type ErlangRebarLockEntry struct {
	Name       string `mapstructure:"name" json:"name"`
	Version    string `mapstructure:"version" json:"version"`
	PkgHash    string `mapstructure:"pkgHash" json:"pkgHash"`
	PkgHashExt string `mapstructure:"pkgHashExt" json:"pkgHashExt"`
}

func (m ErlangRebarLockEntry) Compare(other ErlangRebarLockEntry) int {
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

func (m ErlangRebarLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(ErlangRebarLockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
