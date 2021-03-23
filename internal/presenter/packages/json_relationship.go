package packages

import "github.com/anchore/syft/syft/pkg"

type JSONRelationship struct {
	Parent   string      `json:"parent"`
	Child    string      `json:"child"`
	Type     string      `json:"type"`
	Metadata interface{} `json:"metadata"`
}

func newJSONRelationships(relationships []pkg.Relationship) []JSONRelationship {
	result := make([]JSONRelationship, len(relationships))
	for i, r := range relationships {
		result[i] = JSONRelationship{
			Parent:   string(r.Parent),
			Child:    string(r.Child),
			Type:     string(r.Type),
			Metadata: r.Metadata,
		}
	}
	return result
}
