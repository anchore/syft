package cataloger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_cpeCandidateValues_filter(t *testing.T) {
	tests := []struct {
		name    string
		input   []cpeFieldCandidate
		filters []filterCpeFieldCandidateFn
		expect  []string
	}{
		{
			name: "gocase",
			input: []cpeFieldCandidate{
				{
					value: "allow anything",
				},
				{
					value:                 "no-sub-selections",
					disallowSubSelections: true,
				},
				{
					value:                       "no-delimiter-variations",
					disallowDelimiterVariations: true,
				},
				{
					value:                       "allow nothing",
					disallowSubSelections:       true,
					disallowDelimiterVariations: true,
				},
			},
			expect: []string{
				"allow anything",
				"no-sub-selections",
				"no-delimiter-variations",
				"allow nothing",
			},
		},
		{
			name: "filter sub-selections",
			input: []cpeFieldCandidate{
				{
					value: "allow anything",
				},
				{
					value:                 "no-sub-selections",
					disallowSubSelections: true,
				},
				{
					value:                       "no-delimiter-variations",
					disallowDelimiterVariations: true,
				},
				{
					value:                       "allow nothing",
					disallowSubSelections:       true,
					disallowDelimiterVariations: true,
				},
			},
			filters: []filterCpeFieldCandidateFn{
				filterCandidatesBySubselection,
			},
			expect: []string{
				"allow anything",
				"no-delimiter-variations",
			},
		},
		{
			name: "filter delimiter-variations",
			input: []cpeFieldCandidate{
				{
					value: "allow anything",
				},
				{
					value:                 "no-sub-selections",
					disallowSubSelections: true,
				},
				{
					value:                       "no-delimiter-variations",
					disallowDelimiterVariations: true,
				},
				{
					value:                       "allow nothing",
					disallowSubSelections:       true,
					disallowDelimiterVariations: true,
				},
			},
			filters: []filterCpeFieldCandidateFn{
				filterCandidatesByDelimiterVariations,
			},
			expect: []string{
				"allow anything",
				"no-sub-selections",
			},
		},
		{
			name: "all filters",
			input: []cpeFieldCandidate{
				{
					value: "allow anything",
				},
				{
					value:                 "no-sub-selections",
					disallowSubSelections: true,
				},
				{
					value:                       "no-delimiter-variations",
					disallowDelimiterVariations: true,
				},
				{
					value:                       "allow nothing",
					disallowSubSelections:       true,
					disallowDelimiterVariations: true,
				},
			},
			filters: []filterCpeFieldCandidateFn{
				filterCandidatesByDelimiterVariations,
				filterCandidatesBySubselection,
			},
			expect: []string{
				"allow anything",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := newCPRFieldCandidateSet()
			set.add(test.input...)
			assert.ElementsMatch(t, test.expect, set.values(test.filters...))
		})
	}
}

func Test_cpeFieldCandidateSet_clear(t *testing.T) {
	s := newCPRFieldCandidateSet("1", "2")
	assert.NotEmpty(t, s.values())
	s.clear()
	assert.Empty(t, s.values())
}

func Test_cpeFieldCandidateSet_union(t *testing.T) {
	s1 := newCPRFieldCandidateSet("1", "2")
	assert.Len(t, s1.list(), 2)
	s2 := newCPRFieldCandidateSet("2", "3", "4")
	assert.Len(t, s2.list(), 3)
	s3 := newCPRFieldCandidateSet()
	s3.add(
		cpeFieldCandidate{
			value:                       "1",
			disallowSubSelections:       true,
			disallowDelimiterVariations: false,
		},
		cpeFieldCandidate{
			value:                       "4",
			disallowSubSelections:       false,
			disallowDelimiterVariations: true,
		},
		cpeFieldCandidate{
			value:                       "5",
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		},
	)
	assert.Len(t, s3.list(), 3)

	s1.union(s2, s3)

	// 1 & 4 have duplicate entries since there are candidate conditions set
	assert.ElementsMatch(t, s1.values(), []string{"1", "1", "2", "3", "4", "4", "5"})

	assert.ElementsMatch(t, s1.list(), []cpeFieldCandidate{
		{
			value: "1",
		},
		{
			value:                       "1",
			disallowSubSelections:       true,
			disallowDelimiterVariations: false,
		},
		{
			value: "2",
		},
		{
			value: "3",
		},
		{
			value: "4",
		},
		{
			value:                       "4",
			disallowSubSelections:       false,
			disallowDelimiterVariations: true,
		},
		{
			value:                       "5",
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		},
	})
}

func Test_cpeFieldCandidateSet_union_byValue(t *testing.T) {
	s1 := newCPRFieldCandidateSet("1", "2")
	assert.Len(t, s1.list(), 2)
	s2 := newCPRFieldCandidateSet("2", "3", "4")
	assert.Len(t, s2.list(), 3)
	s3 := newCPRFieldCandidateSet("1", "4", "5")
	assert.Len(t, s3.list(), 3)

	s1.union(s2, s3)

	assert.ElementsMatch(t, s1.values(), []string{"1", "2", "3", "4", "5"})

	assert.ElementsMatch(t, s1.list(), []cpeFieldCandidate{
		{
			value: "1",
		},
		{
			value: "2",
		},
		{
			value: "3",
		},
		{
			value: "4",
		},
		{
			value: "5",
		},
	})
}

func Test_cpeFieldCandidateSet_uniqueValues(t *testing.T) {
	set := newCPRFieldCandidateSet()
	set.add(
		cpeFieldCandidate{
			value: "1",
		},
		cpeFieldCandidate{
			value:                 "1",
			disallowSubSelections: true,
		},
		cpeFieldCandidate{
			value:                       "2",
			disallowDelimiterVariations: true,
		},
		cpeFieldCandidate{
			value: "2",
		},
		cpeFieldCandidate{
			value:                       "3",
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		},
	)

	assert.ElementsMatch(t, []string{"1", "2", "3"}, set.uniqueValues())

}
