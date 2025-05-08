package cpe

import (
	"sort"
)

var _ sort.Interface = (*BySpecificity)(nil)

type BySpecificity []Attributes

func (c BySpecificity) Len() int { return len(c) }

func (c BySpecificity) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

func (c BySpecificity) Less(i, j int) bool {
	return isMoreSpecific(c[i], c[j])
}

// Returns true if i is more specific than j, with some
// tie breaking mechanisms to make sorting equally-specific cpe Attributes
// deterministic.
func isMoreSpecific(i, j Attributes) bool {
	iScore := weightedCountForSpecifiedFields(i)
	jScore := weightedCountForSpecifiedFields(j)

	// check weighted sort first
	if iScore != jScore {
		return iScore > jScore
	}

	// sort longer fields to top
	if countFieldLength(i) != countFieldLength(j) {
		return countFieldLength(i) > countFieldLength(j)
	}

	// if score and length are equal then text sort
	// note that we are not using String from the syft pkg
	// as we are not encoding/decoding this Attributes string so we don't
	// need the proper quoted version of the Attributes.
	return i.BindToFmtString() < j.BindToFmtString()
}

func countFieldLength(cpe Attributes) int {
	return len(cpe.Part + cpe.Vendor + cpe.Product + cpe.Version + cpe.TargetSW)
}

func weightedCountForSpecifiedFields(cpe Attributes) int {
	checksForSpecifiedField := []func(cpe Attributes) (bool, int){
		func(cpe Attributes) (bool, int) { return cpe.Part != "", 2 },
		func(cpe Attributes) (bool, int) { return cpe.Vendor != "", 3 },
		func(cpe Attributes) (bool, int) { return cpe.Product != "", 4 },
		func(cpe Attributes) (bool, int) { return cpe.Version != "", 1 },
		func(cpe Attributes) (bool, int) { return cpe.TargetSW != "", 1 },
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
