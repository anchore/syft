package source

import "github.com/anchore/syft/syft/sort"

type ExcludeConfig struct {
	Paths []string
}

func (ec ExcludeConfig) Compare(other ExcludeConfig) int {
	return sort.CompareArraysOrd(ec.Paths, other.Paths)
}
