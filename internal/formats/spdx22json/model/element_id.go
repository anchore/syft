package model

import "github.com/anchore/syft/internal/formats/common/spdxhelpers"

// ElementID represents the identifier string portion of an SPDX element
// identifier. DocElementID should be used for any attributes which can
// contain identifiers defined in a different SPDX document.
// ElementIDs should NOT contain the mandatory 'SPDXRef-' portion.
type ElementID string

func (e ElementID) String() string {
	return "SPDXRef-" + spdxhelpers.SanitizeElementID(string(e))
}
