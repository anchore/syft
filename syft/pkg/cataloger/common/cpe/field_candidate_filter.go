package cpe

// A fieldCandidateCondition returns true if the condition is true for a given fieldCandidate.
type fieldCandidateCondition func(fieldCandidate) bool

func subSelectionsDisallowed(c fieldCandidate) bool {
	return c.disallowSubSelections
}

func delimiterVariationsDisallowed(c fieldCandidate) bool {
	return c.disallowDelimiterVariations
}

func valueEquals(v string) fieldCandidateCondition {
	return func(candidate fieldCandidate) bool {
		return candidate.value == v
	}
}
