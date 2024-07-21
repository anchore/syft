package relationships

import (
	"slices"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

type Index struct {
	byFromID map[artifact.ID][]artifact.Relationship
	byToID   map[artifact.ID][]artifact.Relationship
}

// NewIndex returns a new relationship Index
func NewIndex(relationships []artifact.Relationship) *Index {
	out := &Index{
		byFromID: map[artifact.ID][]artifact.Relationship{},
		byToID:   map[artifact.ID][]artifact.Relationship{},
	}

	fromIDs := map[artifact.ID][]sortableRelationship{}
	toIDs := map[artifact.ID][]sortableRelationship{}

	// store appropriate indexes for stable ordering to minimize ID() calls
	for _, r := range relationships {
		fromID := r.From.ID()
		toID := r.To.ID()

		fromIDs[fromID] = append(fromIDs[fromID], sortableRelationship{string(toID), r})
		out.byToID[toID] = append(out.byToID[toID], r)
	}

	for k, v := range fromIDs {
		out.byFromID[k] = collect(v)
	}

	for k, v := range toIDs {
		out.byToID[k] = collect(v)
	}

	return out
}

// From returns all relationships from the given identifiable type
func (i *Index) From(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	if identifiable == nil {
		return nil
	}
	var out []artifact.Relationship
	for _, r := range i.byFromID[identifiable.ID()] {
		if len(types) == 0 || slices.Contains(types, r.Type) {
			out = append(out, r)
		}
	}
	return out
}

// To returns all relationships to the given identifiable type
func (i *Index) To(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	if identifiable == nil {
		return nil
	}
	var out []artifact.Relationship
	for _, r := range i.byToID[identifiable.ID()] {
		if len(types) == 0 || slices.Contains(types, r.Type) {
			out = append(out, r)
		}
	}
	return out
}

// ToAndFrom returns all relationships to or from the given identifiable type
func (i *Index) ToAndFrom(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return append(i.To(identifiable, types...), i.From(identifiable, types...)...)
}

// Coordinates returns all coordinates for the provided identifiable for provided relationship types
// If no types are provided, all relationship types are considered.
func (i *Index) Coordinates(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []file.Coordinates {
	var coordinates []file.Coordinates
	for _, relationship := range i.ToAndFrom(identifiable, types...) {
		cords := extractCoordinates(relationship)
		coordinates = append(coordinates, cords...)
	}
	return coordinates
}

func extractCoordinates(relationship artifact.Relationship) (results []file.Coordinates) {
	if coordinates, exists := relationship.From.(file.Coordinates); exists {
		results = append(results, coordinates)
	}

	if coordinates, exists := relationship.To.(file.Coordinates); exists {
		results = append(results, coordinates)
	}

	return results
}

type sortableRelationship struct {
	key string
	rel artifact.Relationship
}

func collect(relationships []sortableRelationship) []artifact.Relationship {
	slices.SortFunc(relationships, sortFunc)

	var out []artifact.Relationship
	for _, rel := range relationships {
		out = append(out, rel.rel)
	}
	return out
}

func sortFunc(a, b sortableRelationship) int {
	cmp := strings.Compare(string(a.rel.Type), string(b.rel.Type))
	if cmp != 0 {
		return cmp
	}
	return strings.Compare(a.key, b.key)
}
