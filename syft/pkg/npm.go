package pkg

import "github.com/anchore/syft/syft/sort"

// NpmPackage represents the contents of a javascript package.json file.
type NpmPackage struct {
	Name        string `mapstructure:"name" json:"name"`
	Version     string `mapstructure:"version" json:"version"`
	Author      string `mapstructure:"author" json:"author"`
	Homepage    string `mapstructure:"homepage" json:"homepage"`
	Description string `mapstructure:"description" json:"description"`
	URL         string `mapstructure:"url" json:"url"`
	Private     bool   `mapstructure:"private" json:"private"`
}

// NpmPackageLockEntry represents a single entry within the "packages" section of a package-lock.json file.
type NpmPackageLockEntry struct {
	Resolved  string `mapstructure:"resolved" json:"resolved"`
	Integrity string `mapstructure:"integrity" json:"integrity"`
}

// YarnLockEntry represents a single entry section of a yarn.lock file.
type YarnLockEntry struct {
	Resolved  string `mapstructure:"resolved" json:"resolved"`
	Integrity string `mapstructure:"integrity" json:"integrity"`
}

func (p NpmPackageLockEntry) Compare(other NpmPackageLockEntry) int {
	if i := sort.CompareOrd(p.Resolved, other.Resolved); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Integrity, other.Integrity); i != 0 {
		return i
	}
	return 0
}
func (p YarnLockEntry) Compare(other YarnLockEntry) int {
	if i := sort.CompareOrd(p.Resolved, other.Resolved); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Integrity, other.Integrity); i != 0 {
		return i
	}
	return 0
}
func (p NpmPackage) Compare(other NpmPackage) int {
	if i := sort.CompareOrd(p.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Author, other.Author); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Homepage, other.Homepage); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Description, other.Description); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.URL, other.URL); i != 0 {
		return i
	}
	if p.Private != other.Private {
		if p.Private {
			return 1
		}
		return -1
	}
	return 0
}
func (p NpmPackage) TryCompare(other any) (bool, int) {
	if other, exists := other.(NpmPackage); exists {
		return true, p.Compare(other)
	}
	return false, 0
}
func (p NpmPackageLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(NpmPackageLockEntry); exists {
		return true, p.Compare(other)
	}
	return false, 0
}
func (p YarnLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(YarnLockEntry); exists {
		return true, p.Compare(other)
	}
	return false, 0
}
