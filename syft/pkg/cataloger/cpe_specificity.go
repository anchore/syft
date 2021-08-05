package cataloger

import (
	"sort"

	"github.com/facebookincubator/nvdtools/wfn"
)

var _ sort.Interface = (*ByCPESpecificity)(nil)

type ByCPESpecificity []wfn.Attributes

func (c ByCPESpecificity) Len() int      { return len(c) }
func (c ByCPESpecificity) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c ByCPESpecificity) Less(i, j int) bool {
	iScore := countSpecifiedFields(c[i])
	jScore := countSpecifiedFields(c[j])
	if iScore == jScore {
		return countFieldLength(c[i]) > countFieldLength(c[j])
	}
	return iScore > jScore
}

func countFieldLength(cpe wfn.Attributes) int {
	return len(cpe.Part + cpe.Vendor + cpe.Product + cpe.Version + cpe.TargetSW)
}

func countSpecifiedFields(cpe wfn.Attributes) int {
	checksForSpecifiedField := []func(cpe wfn.Attributes) (bool, int){
		func(cpe wfn.Attributes) (bool, int) { return cpe.Part != "", 2 },
		func(cpe wfn.Attributes) (bool, int) { return cpe.Vendor != "", 3 },
		func(cpe wfn.Attributes) (bool, int) { return cpe.Product != "", 4 },
		func(cpe wfn.Attributes) (bool, int) { return cpe.Version != "", 1 },
		func(cpe wfn.Attributes) (bool, int) { return cpe.TargetSW != "", 1 },
	}

	var weightedCount int
	for _, fieldIsSpecified := range checksForSpecifiedField {
		isSpecified, weight := fieldIsSpecified(cpe)
		if isSpecified {
			weightedCount += weight
		}
	}

	return weightedCount
}
