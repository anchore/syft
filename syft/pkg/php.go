package pkg

import "github.com/anchore/syft/syft/sort"

// PhpComposerInstalledEntry represents a single package entry from a composer v1/v2 "installed.json" files (very similar to composer.lock files).
type PhpComposerInstalledEntry PhpComposerLockEntry

// PhpComposerLockEntry represents a single package entry found from a composer.lock file.
type PhpComposerLockEntry struct {
	Name            string                       `json:"name"`
	Version         string                       `json:"version"`
	Source          PhpComposerExternalReference `json:"source"`
	Dist            PhpComposerExternalReference `json:"dist"`
	Require         map[string]string            `json:"require,omitempty"`
	Provide         map[string]string            `json:"provide,omitempty"`
	RequireDev      map[string]string            `json:"require-dev,omitempty"`
	Suggest         map[string]string            `json:"suggest,omitempty"`
	License         []string                     `json:"license,omitempty"`
	Type            string                       `json:"type,omitempty"`
	NotificationURL string                       `json:"notification-url,omitempty"`
	Bin             []string                     `json:"bin,omitempty"`
	Authors         []PhpComposerAuthors         `json:"authors,omitempty"`
	Description     string                       `json:"description,omitempty"`
	Homepage        string                       `json:"homepage,omitempty"`
	Keywords        []string                     `json:"keywords,omitempty"`
	Time            string                       `json:"time,omitempty"`
}

type PhpComposerExternalReference struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
	Shasum    string `json:"shasum,omitempty"`
}

type PhpComposerAuthors struct {
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
	Homepage string `json:"homepage,omitempty"`
}

type PhpPeclEntry struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	License []string `json:"license,omitempty"`
}

func (m PhpComposerExternalReference) Compare(other PhpComposerExternalReference) int {
	if i := sort.CompareOrd(m.Type, other.Type); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.URL, other.URL); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Reference, other.Reference); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Shasum, other.Shasum); i != 0 {
		return i
	}
	return 0
}
func (m PhpComposerAuthors) Compare(other PhpComposerAuthors) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Email, other.Email); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Homepage, other.Homepage); i != 0 {
		return i
	}
	return 0
}
func (m PhpPeclEntry) Compare(other PhpPeclEntry) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.License, other.License); i != 0 {
		return i
	}
	return 0
}
func (m PhpComposerLockEntry) Compare(other PhpComposerLockEntry) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.Compare(m.Source, other.Source); i != 0 {
		return i
	}
	if i := sort.Compare(m.Dist, other.Dist); i != 0 {
		return i
	}
	if i := sort.CompareMapOrd(m.Require, other.Require); i != 0 {
		return i
	}
	if i := sort.CompareMapOrd(m.Provide, other.Provide); i != 0 {
		return i
	}
	if i := sort.CompareMapOrd(m.RequireDev, other.RequireDev); i != 0 {
		return i
	}
	if i := sort.CompareMapOrd(m.Suggest, other.Suggest); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.License, other.License); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Type, other.Type); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.NotificationURL, other.NotificationURL); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Bin, other.Bin); i != 0 {
		return i
	}
	if i := sort.CompareArrays(m.Authors, other.Authors); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Description, other.Description); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Homepage, other.Homepage); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Keywords, other.Keywords); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Time, other.Time); i != 0 {
		return i
	}
	return 0
}
func (m PhpComposerLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(PhpComposerLockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}

func (m PhpComposerInstalledEntry) Compare(other PhpComposerInstalledEntry) int {
	return sort.Compare(PhpComposerLockEntry(m), PhpComposerLockEntry(other))
}

func (m PhpComposerInstalledEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(PhpComposerInstalledEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
func (m PhpPeclEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(PhpPeclEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
