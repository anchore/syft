package json

import "github.com/anchore/syft/syft/pkg"

type Relationship struct {
	Parent   string      `json:"parent"`
	Child    string      `json:"child"`
	Type     string      `json:"type"`
	Metadata interface{} `json:"metadata"`
}

func newRelationships(relationships []pkg.Relationship) []Relationship {
	result := make([]Relationship, len(relationships))
	for i, r := range relationships {
		result[i] = Relationship{
			Parent:   string(r.Parent),
			Child:    string(r.Child),
			Type:     string(r.Type),
			Metadata: r.Metadata,
		}
	}
	return result
}
