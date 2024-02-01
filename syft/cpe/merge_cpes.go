package cpe

import (
	"fmt"
	"sort"
)

func Merge(a, b []Attributes) (result []Attributes) {
	aCPEs := make(map[string]Attributes)

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
func MergeSourcedCPEs(a, b []CPE) []CPE {
	var result []CPE
	dedupe := make(map[string]CPE)
	key := func(scpe CPE) string {
		return fmt.Sprintf("%s:%s", scpe.Source.String(), scpe.Attributes.String())
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
	sort.Sort(BySourceThenSpecificity(result))
	return result
}
