package spdx22

// ElementID represents the identifier string portion of an SPDX element
// identifier. DocElementID should be used for any attributes which can
// contain identifiers defined in a different SPDX document.
// ElementIDs should NOT contain the mandatory 'SPDXRef-' portion.
type ElementID string

func (e ElementID) String() string {
	return "SPDXRef-" + string(e)
}

// DocElementID represents an SPDX element identifier that could be defined
// in a different SPDX document, and therefore could have a "DocumentRef-"
// portion, such as Relationship and Annotations.
// ElementID is used for attributes in which a "DocumentRef-" portion cannot
// appear, such as a Package or File definition (since it is necessarily
// being defined in the present document).
// DocumentRefID will be the empty string for elements defined in the
// present document.
// DocElementIDs should NOT contain the mandatory 'DocumentRef-' or
// 'SPDXRef-' portions.
type DocElementID struct {
	DocumentRefID string
	ElementRefID  ElementID
}

// RenderDocElementID takes a DocElementID and returns the string equivalent,
// with the SPDXRef- prefix (and, if applicable, the DocumentRef- prefix)
// reinserted.
func (d DocElementID) String() string {
	prefix := ""
	if d.DocumentRefID != "" {
		prefix = "DocumentRef-" + d.DocumentRefID + ":"
	}
	return prefix + d.ElementRefID.String()
}
