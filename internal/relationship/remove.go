package relationship

import "github.com/anchore/syft/syft/artifact"

// TODO: put under test...
func RemoveRelationshipsByID(relationships []artifact.Relationship, id artifact.ID) []artifact.Relationship {
	var filtered []artifact.Relationship
	for _, r := range relationships {
		if r.To.ID() != id && r.From.ID() != id {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
