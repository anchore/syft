package cpe

import (
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
