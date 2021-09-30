package cpe

import (
	"sort"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

var _ sort.Interface = (*BySpecificity)(nil)

type BySpecificity []wfn.Attributes

func (c BySpecificity) Len() int { return len(c) }

func (c BySpecificity) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

func (c BySpecificity) Less(i, j int) bool {
	iScore := weightedCountForSpecifiedFields(c[i])
	jScore := weightedCountForSpecifiedFields(c[j])

	if iScore == jScore {
		if countFieldLength(c[i]) == countFieldLength(c[j]) {
			// lower index count preferred
			return dashIndex(c[i]) > dashIndex(c[j])
		}

		return countFieldLength(c[i]) > countFieldLength(c[j])
	}
	return iScore > jScore
}

// if countFieldLength is equal for adjacent members
// Less has the option of randomly ordering the items
// dashIndex is used to stabilize the sort so that Vendor
// and Product combinations are given a stable hierarchy
// if their countFieldLength sums are equal.
func dashIndex(cpe wfn.Attributes) int {
	count := 0
	dash := "-"
	if strings.Contains(cpe.Vendor, dash) {
		count += 2
	}

	if strings.Contains(cpe.Product, dash) {
		count++
	}

	return count
}

func countFieldLength(cpe wfn.Attributes) int {
	return len(cpe.Part + cpe.Vendor + cpe.Product + cpe.Version + cpe.TargetSW)
}

func weightedCountForSpecifiedFields(cpe wfn.Attributes) int {
	checksForSpecifiedField := []func(cpe wfn.Attributes) (bool, int){
		func(cpe wfn.Attributes) (bool, int) { return cpe.Part != "", 2 },
		func(cpe wfn.Attributes) (bool, int) { return cpe.Vendor != "", 3 },
		func(cpe wfn.Attributes) (bool, int) { return cpe.Product != "", 4 },
		func(cpe wfn.Attributes) (bool, int) { return cpe.Version != "", 1 },
		func(cpe wfn.Attributes) (bool, int) { return cpe.TargetSW != "", 1 },
	}

	weightedCount := 0
	for _, fieldIsSpecified := range checksForSpecifiedField {
		isSpecified, weight := fieldIsSpecified(cpe)
		if isSpecified {
			weightedCount += weight
		}
	}

	return weightedCount
}
