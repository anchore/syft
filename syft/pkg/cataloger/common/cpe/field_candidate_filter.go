package cpe

// filterFieldCandidateFn instances should return true if the given fieldCandidate should be removed from a collection
type filterFieldCandidateFn func(fieldCandidate) bool

func filterOutBySubselection(c fieldCandidate) bool {
	return c.disallowSubSelections
}

func filterOutByDelimiterVariations(c fieldCandidate) bool {
	return c.disallowDelimiterVariations
}
