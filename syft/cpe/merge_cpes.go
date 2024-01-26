package cpe

import (
	"fmt"
	"sort"
)

func Merge(a, b []CPE) (result []CPE) {
	aCPEs := make(map[string]CPE)

	// keep all CPEs from a and create a quick string-based lookup
	for _, aCPE := range a {
		aCPEs[aCPE.BindToFmtString()] = aCPE
		result = append(result, aCPE)
	}

	// keep all unique CPEs from b
	for _, bCPE := range b {
		if _, exists := aCPEs[bCPE.BindToFmtString()]; !exists {
			result = append(result, bCPE)
		}
	}

	sort.Sort(BySpecificity(result))
	return result
}

// MergeSourcedCPEs returns unique SourcedCPEs that are found in A or B
// Two SourcedCPEs are identical if their source and normalized string are identical
func MergeSourcedCPEs(a, b []SourcedCPE) []SourcedCPE {
	var result []SourcedCPE
	dedupe := make(map[string]SourcedCPE)
	key := func(scpe SourcedCPE) string {
		return fmt.Sprintf("%s:%s", scpe.Source.String(), scpe.CPE.String())
	}
	for _, s := range a {
		dedupe[key(s)] = s
	}
	for _, s := range b {
		dedupe[key(s)] = s
	}
	for _, val := range dedupe {
		result = append(result, val)
	}
	// TODO: deterministic sort!
	return result
}
