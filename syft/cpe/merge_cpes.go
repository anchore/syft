package cpe

import (
	"fmt"
	"sort"
)

// Merge returns unique SourcedCPEs that are found in A or B
// Two SourcedCPEs are identical if their source and normalized string are identical
func Merge(a, b []CPE) []CPE {
	var result []CPE
	dedupe := make(map[string]CPE)
	key := func(scpe CPE) string {
		return fmt.Sprintf("%s:%s", scpe.Source.String(), scpe.Attributes.BindToFmtString())
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
