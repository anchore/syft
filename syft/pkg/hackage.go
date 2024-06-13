package pkg

import "github.com/anchore/syft/syft/sort"

// HackageStackYamlLockEntry represents a single entry from the "packages" section of a stack.yaml.lock file.
type HackageStackYamlLockEntry struct {
	PkgHash     string `mapstructure:"pkgHash" json:"pkgHash,omitempty"`
	SnapshotURL string `mapstructure:"snapshotURL" json:"snapshotURL,omitempty"`
}

// HackageStackYamlEntry represents a single entry from the "extra-deps" section of a stack.yaml file.
type HackageStackYamlEntry struct {
	PkgHash string `mapstructure:"pkgHash" json:"pkgHash,omitempty"`
}

func (m HackageStackYamlLockEntry) Compare(other HackageStackYamlLockEntry) int {
	if i := sort.CompareOrd(m.PkgHash, other.PkgHash); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.SnapshotURL, other.SnapshotURL); i != 0 {
		return i
	}
	return 0
}

func (m HackageStackYamlLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(HackageStackYamlLockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}

func (m HackageStackYamlEntry) Compare(other HackageStackYamlEntry) int {
	if i := sort.CompareOrd(m.PkgHash, other.PkgHash); i != 0 {
		return i
	}
	return 0
}

func (m HackageStackYamlEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(HackageStackYamlEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
