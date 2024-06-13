package pkg

import "github.com/anchore/syft/syft/sort"

// DotnetDepsEntry is a struct that represents a single entry found in the "libraries" section in a .NET [*.]deps.json file.
type DotnetDepsEntry struct {
	Name     string `mapstructure:"name" json:"name"`
	Version  string `mapstructure:"version" json:"version"`
	Path     string `mapstructure:"path" json:"path"`
	Sha512   string `mapstructure:"sha512" json:"sha512"`
	HashPath string `mapstructure:"hashPath" json:"hashPath"`
}

// DotnetPortableExecutableEntry is a struct that represents a single entry found within "VersionResources" section of a .NET Portable Executable binary file.
type DotnetPortableExecutableEntry struct {
	AssemblyVersion string `json:"assemblyVersion"`
	LegalCopyright  string `json:"legalCopyright"`
	Comments        string `json:"comments,omitempty"`
	InternalName    string `json:"internalName,omitempty"`
	CompanyName     string `json:"companyName"`
	ProductName     string `json:"productName"`
	ProductVersion  string `json:"productVersion"`
}

func (m DotnetDepsEntry) Compare(other DotnetDepsEntry) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Sha512, other.Sha512); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.HashPath, other.HashPath); i != 0 {
		return i
	}
	return 0
}
func (m DotnetPortableExecutableEntry) Compare(other DotnetPortableExecutableEntry) int {
	if i := sort.CompareOrd(m.AssemblyVersion, other.AssemblyVersion); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.LegalCopyright, other.LegalCopyright); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Comments, other.Comments); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.InternalName, other.InternalName); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.CompanyName, other.CompanyName); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.ProductName, other.ProductName); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.ProductVersion, other.ProductVersion); i != 0 {
		return i
	}
	return 0
}
func (m DotnetDepsEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(DotnetDepsEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
func (m DotnetPortableExecutableEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(DotnetPortableExecutableEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
