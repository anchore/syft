package cataloger

import "github.com/facebookincubator/nvdtools/wfn"

type ByCPESpecificity []wfn.Attributes

// Implementing sort.Interface
func (c ByCPESpecificity) Len() int      { return len(c) }
func (c ByCPESpecificity) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c ByCPESpecificity) Less(i, j int) bool {
	return countSpecifiedFields(c[i]) > countSpecifiedFields(c[j])
}

func countSpecifiedFields(cpe wfn.Attributes) int {
	checksForSpecifiedField := []func(cpe wfn.Attributes) bool{
		func(cpe wfn.Attributes) bool { return cpe.Part != "" },
		func(cpe wfn.Attributes) bool { return cpe.Product != "" },
		func(cpe wfn.Attributes) bool { return cpe.Vendor != "" },
		func(cpe wfn.Attributes) bool { return cpe.Version != "" },
		func(cpe wfn.Attributes) bool { return cpe.TargetSW != "" },
	}

	count := 0
	for _, fieldIsSpecified := range checksForSpecifiedField {
		if fieldIsSpecified(cpe) {
			count++
		}
	}

	return count
}
