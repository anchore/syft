package cataloger

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/scylladb/go-set/strset"
)

// this is a static mapping of known package names (keys) to official cpe names for each package
type candidatesByPackageType map[pkg.Type]map[string][]string

type filterCpeFieldCandidateFn func(cpeFieldCandidate) bool

type cpeFieldCandidate struct {
	value                       string
	disallowSubSelections       bool
	disallowDelimiterVariations bool
}

type cpeFieldCandidateSet struct {
	candidates map[cpeFieldCandidate]struct{}
}

func filterCandidatesBySubselection(c cpeFieldCandidate) bool {
	return c.disallowSubSelections
}

func filterCandidatesByDelimiterVariations(c cpeFieldCandidate) bool {
	return c.disallowDelimiterVariations
}

func newCPRFieldCandidateFromSets(sets ...*cpeFieldCandidateSet) *cpeFieldCandidateSet {
	s := newCPRFieldCandidateSet()
	for _, set := range sets {
		s.add(set.list()...)
	}
	return s
}

func newCPRFieldCandidateSet(values ...string) *cpeFieldCandidateSet {
	s := &cpeFieldCandidateSet{
		candidates: make(map[cpeFieldCandidate]struct{}),
	}
	s.addValue(values...)
	return s
}

func (s *cpeFieldCandidateSet) addValue(values ...string) {
	for _, value := range values {
		// default candidate as an allow-all
		candidate := cpeFieldCandidate{
			value: value,
		}
		s.candidates[candidate] = struct{}{}
	}
}

func (s *cpeFieldCandidateSet) add(candidates ...cpeFieldCandidate) {
	for _, candidate := range candidates {
		s.candidates[candidate] = struct{}{}
	}
}

func (s *cpeFieldCandidateSet) clear() {
	s.candidates = make(map[cpeFieldCandidate]struct{})
}

func (s *cpeFieldCandidateSet) union(others ...*cpeFieldCandidateSet) {
	for _, other := range others {
		s.add(other.list()...)
	}
}

func (s *cpeFieldCandidateSet) list(filters ...filterCpeFieldCandidateFn) (results []cpeFieldCandidate) {
candidateLoop:
	for c := range s.candidates {
		for _, fn := range filters {
			if fn(c) {
				continue candidateLoop
			}
		}
		results = append(results, c)
	}
	return results
}

func (s *cpeFieldCandidateSet) values(filters ...filterCpeFieldCandidateFn) (results []string) {
	for _, c := range s.list(filters...) {
		results = append(results, c.value)
	}
	return results
}

func (s *cpeFieldCandidateSet) uniqueValues(filters ...filterCpeFieldCandidateFn) []string {
	return strset.New(s.values(filters...)...).List()
}

func (s candidatesByPackageType) getCandidates(t pkg.Type, key string) []string {
	if _, ok := s[t]; !ok {
		return nil
	}
	value, ok := s[t][key]
	if !ok {
		return nil
	}

	return value
}
