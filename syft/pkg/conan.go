package pkg

import "github.com/anchore/syft/syft/sort"

// ConanV1LockEntry represents a single "node" entry from a conan.lock V1 file.
type ConanV1LockEntry struct {
	Ref            string    `json:"ref"`
	PackageID      string    `json:"package_id,omitempty"`
	Prev           string    `json:"prev,omitempty"`
	Requires       []string  `json:"requires,omitempty"`
	BuildRequires  []string  `json:"build_requires,omitempty"`
	PythonRequires []string  `json:"py_requires,omitempty"`
	Options        KeyValues `json:"options,omitempty"`
	Path           string    `json:"path,omitempty"`
	Context        string    `json:"context,omitempty"`
}

// ConanV2LockEntry represents a single "node" entry from a conan.lock V2 file.
type ConanV2LockEntry struct {
	Ref             string `json:"ref"`
	PackageID       string `json:"packageID,omitempty"`
	Username        string `json:"username,omitempty"`
	Channel         string `json:"channel,omitempty"`
	RecipeRevision  string `json:"recipeRevision,omitempty"`
	PackageRevision string `json:"packageRevision,omitempty"`
	TimeStamp       string `json:"timestamp,omitempty"`
}

// ConanfileEntry represents a single "Requires" entry from a conanfile.txt.
type ConanfileEntry struct {
	Ref string `mapstructure:"ref" json:"ref"`
}

// ConaninfoEntry represents a single "full_requires" entry from a conaninfo.txt.
type ConaninfoEntry struct {
	Ref       string `json:"ref"`
	PackageID string `json:"package_id,omitempty"`
}

func (m ConaninfoEntry) Compare(other ConaninfoEntry) int {
	if i := sort.CompareOrd(m.Ref, other.Ref); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.PackageID, other.PackageID); i != 0 {
		return i
	}
	return 0
}
func (m ConanfileEntry) Compare(other ConanfileEntry) int {
	if i := sort.CompareOrd(m.Ref, other.Ref); i != 0 {
		return i
	}
	return 0
}
func (m ConanV2LockEntry) Compare(other ConanV2LockEntry) int {
	if i := sort.CompareOrd(m.Ref, other.Ref); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.PackageID, other.PackageID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Username, other.Username); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Channel, other.Channel); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.RecipeRevision, other.RecipeRevision); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.PackageRevision, other.PackageRevision); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.TimeStamp, other.TimeStamp); i != 0 {
		return i
	}
	return 0
}
func (m ConanV1LockEntry) Compare(other ConanV1LockEntry) int {
	if i := sort.CompareOrd(m.Ref, other.Ref); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.PackageID, other.PackageID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Prev, other.Prev); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Requires, other.Requires); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.BuildRequires, other.BuildRequires); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.PythonRequires, other.PythonRequires); i != 0 {
		return i
	}
	if i := sort.CompareArrays(m.Options, other.Options); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Context, other.Context); i != 0 {
		return i
	}
	return 0
}
func (m ConanV1LockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(ConanV1LockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
func (m ConanV2LockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(ConanV2LockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
func (m ConanfileEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(ConanfileEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
func (m ConaninfoEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(ConaninfoEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
