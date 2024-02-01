package cpe

import (
	"sort"
)

var _ sort.Interface = (*BySpecificity)(nil)

type BySpecificity []Attributes

func (c BySpecificity) Len() int { return len(c) }

func (c BySpecificity) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

func (c BySpecificity) Less(i, j int) bool {
	iScore := weightedCountForSpecifiedFields(c[i])
	jScore := weightedCountForSpecifiedFields(c[j])

	// check weighted sort first
	if iScore != jScore {
		return iScore > jScore
	}

	// sort longer fields to top
	if countFieldLength(c[i]) != countFieldLength(c[j]) {
		return countFieldLength(c[i]) > countFieldLength(c[j])
	}

	// if score and length are equal then text sort
	// note that we are not using String from the syft pkg
	// as we are not encoding/decoding this Attributes string so we don't
	// need the proper quoted version of the Attributes.
	return c[i].BindToFmtString() < c[j].BindToFmtString()
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
