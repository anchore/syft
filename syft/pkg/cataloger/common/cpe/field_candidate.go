package cpe

import (
	"github.com/scylladb/go-set/strset"
)

type fieldCandidate struct {
	value                       string
	disallowSubSelections       bool
	disallowDelimiterVariations bool
}

type fieldCandidateSet struct {
	candidates map[fieldCandidate]struct{}
}

func newCPRFieldCandidateFromSets(sets ...*fieldCandidateSet) *fieldCandidateSet {
	s := newCPRFieldCandidateSet()
	for _, set := range sets {
		s.add(set.list()...)
	}
	return s
}

func newCPRFieldCandidateSet(values ...string) *fieldCandidateSet {
	s := &fieldCandidateSet{
		candidates: make(map[fieldCandidate]struct{}),
	}
	s.addValue(values...)
	return s
}

func (s *fieldCandidateSet) addValue(values ...string) {
	for _, value := range values {
		// default candidate as an allow-all
		candidate := fieldCandidate{
			value: value,
		}
		s.candidates[candidate] = struct{}{}
	}
}

func (s *fieldCandidateSet) add(candidates ...fieldCandidate) {
	for _, candidate := range candidates {
		s.candidates[candidate] = struct{}{}
	}
}

func (s *fieldCandidateSet) clear() {
	s.candidates = make(map[fieldCandidate]struct{})
}

func (s *fieldCandidateSet) union(others ...*fieldCandidateSet) {
	for _, other := range others {
		s.add(other.list()...)
	}
}

func (s *fieldCandidateSet) list(filters ...filterFieldCandidateFn) (results []fieldCandidate) {
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

func (s *fieldCandidateSet) values(filters ...filterFieldCandidateFn) (results []string) {
	for _, c := range s.list(filters...) {
		results = append(results, c.value)
	}
	return results
}

func (s *fieldCandidateSet) uniqueValues(filters ...filterFieldCandidateFn) []string {
	return strset.New(s.values(filters...)...).List()
}
