package cpe

type filterFieldCandidateFn func(fieldCandidate) bool

func filterFieldCandidatesBySubselection(c fieldCandidate) bool {
	return c.disallowSubSelections
}

func filterFieldCandidatesByDelimiterVariations(c fieldCandidate) bool {
	return c.disallowDelimiterVariations
}
