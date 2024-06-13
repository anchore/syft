package pkg

import "github.com/anchore/syft/syft/sort"

type LuaRocksPackage struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	License      string            `json:"license"`
	Homepage     string            `json:"homepage"`
	Description  string            `json:"description"`
	URL          string            `json:"url"`
	Dependencies map[string]string `json:"dependencies"`
}

func (m LuaRocksPackage) Compare(other LuaRocksPackage) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.License, other.License); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Homepage, other.Homepage); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Description, other.Description); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.URL, other.URL); i != 0 {
		return i
	}
	if i := sort.CompareMapOrd(m.Dependencies, other.Dependencies); i != 0 {
		return i
	}
	return 0
}

func (m LuaRocksPackage) TryCompare(other any) (bool, int) {
	if other, exists := other.(LuaRocksPackage); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
