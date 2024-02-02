package cpe

import "sort"

type BySourceThenSpecificity []CPE

func (b BySourceThenSpecificity) Len() int {
	return len(b)
}

func (b BySourceThenSpecificity) Less(i, j int) bool {
	sourceOrder := map[Source]int{
		NVDDictionaryLookupSource: 1,
		DeclaredSource:            2,
		GeneratedSource:           3,
	}

	getRank := func(source Source) int {
		if rank, exists := sourceOrder[source]; exists {
			return rank
		}
		return 4 // Sourced we don't know about can't be assigned special priority, so
		// are considered ties.
	}
	iSource := b[i].Source
	jSource := b[j].Source
	rankI, rankJ := getRank(iSource), getRank(jSource)
	if rankI != rankJ {
		return rankI < rankJ
	}

	return isMoreSpecific(b[i].Attributes, b[j].Attributes)
}

func (b BySourceThenSpecificity) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

var _ sort.Interface = (*BySourceThenSpecificity)(nil)
