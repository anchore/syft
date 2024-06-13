package pkg

import "github.com/anchore/syft/syft/sort"

type RustCargoLockEntry struct {
	Name         string   `toml:"name" json:"name"`
	Version      string   `toml:"version" json:"version"`
	Source       string   `toml:"source" json:"source"`
	Checksum     string   `toml:"checksum" json:"checksum"`
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}

type RustBinaryAuditEntry struct {
	Name    string `toml:"name" json:"name"`
	Version string `toml:"version" json:"version"`
	Source  string `toml:"source" json:"source"`
}

func (m RustCargoLockEntry) Compare(other RustCargoLockEntry) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Source, other.Source); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Checksum, other.Checksum); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Dependencies, other.Dependencies); i != 0 {
		return i
	}
	return 0
}

func (m RustCargoLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(RustCargoLockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}

func (m RustBinaryAuditEntry) Compare(other RustBinaryAuditEntry) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Source, other.Source); i != 0 {
		return i
	}
	return 0
}

func (m RustBinaryAuditEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(RustBinaryAuditEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
