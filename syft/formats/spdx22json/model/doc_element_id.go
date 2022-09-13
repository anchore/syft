package model

import "github.com/anchore/syft/internal/formats/common/spdxhelpers"

// DocElementID represents the identifier string portion of an SPDX document
// identifier. It should be to used to reference any other SPDX document.
// DocElementIDs should NOT contain the 'DOCUMENTREF-' portion.
type DocElementID string

func (d DocElementID) String() string {
	return "DocumentRef-" + spdxhelpers.SanitizeElementID(string(d))
}
