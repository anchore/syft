package relationship

import (
	"slices"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

// Index indexes relationships, preventing duplicates
type Index struct {
	all    []*sortableRelationship
	fromID map[artifact.ID]*mappedRelationships
	toID   map[artifact.ID]*mappedRelationships
}

// NewIndex returns a new relationship Index
func NewIndex(relationships ...artifact.Relationship) *Index {
	out := Index{}
	out.Add(relationships...)
	return &out
}

// Add adds all the given relationships to the index, without adding duplicates
func (i *Index) Add(relationships ...artifact.Relationship) {
	if i.fromID == nil {
		i.fromID = map[artifact.ID]*mappedRelationships{}
	}
	if i.toID == nil {
		i.toID = map[artifact.ID]*mappedRelationships{}
	}

	// store appropriate indexes for stable ordering to minimize ID() calls
	for _, r := range relationships {
		// prevent duplicates
		if i.Contains(r) {
			continue
		}

		fromID := r.From.ID()
		toID := r.To.ID()

		relationship := &sortableRelationship{
			from:         fromID,
			to:           toID,
			relationship: r,
		}

		// add to all relationships
		i.all = append(i.all, relationship)

		// add from -> to mapping
		mapped := i.fromID[fromID]
		if mapped == nil {
			mapped = &mappedRelationships{}
			i.fromID[fromID] = mapped
		}
		mapped.add(toID, relationship)

		// add to -> from mapping
		mapped = i.toID[toID]
		if mapped == nil {
			mapped = &mappedRelationships{}
			i.toID[toID] = mapped
		}
		mapped.add(fromID, relationship)
	}
}

// From returns all relationships from the given identifiable, with specified types
func (i *Index) From(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return toSortedSlice(fromMapped(i.fromID, identifiable), types)
}

// To returns all relationships to the given identifiable, with specified types
func (i *Index) To(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return toSortedSlice(fromMapped(i.toID, identifiable), types)
}

// References returns all relationships that reference to or from the given identifiable
func (i *Index) References(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return toSortedSlice(append(fromMapped(i.fromID, identifiable), fromMapped(i.toID, identifiable)...), types)
}

// Coordinates returns all coordinates for the provided identifiable for provided relationship types
// If no types are provided, all relationship types are considered.
func (i *Index) Coordinates(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []file.Coordinates {
	var coordinates []file.Coordinates
	for _, relationship := range i.References(identifiable, types...) {
		cords := extractCoordinates(relationship)
		coordinates = append(coordinates, cords...)
	}
	return coordinates
}

// Contains indicates the relationship is present in this index
func (i *Index) Contains(r artifact.Relationship) bool {
	if mapped := i.fromID[r.From.ID()]; mapped != nil {
		if ids := mapped.typeMap[r.Type]; ids != nil {
			return ids[r.To.ID()] != nil
		}
	}
	return false
}

// All returns a sorted set of relationships matching all types, or all relationships if no types specified
func (i *Index) All(types ...artifact.RelationshipType) []artifact.Relationship {
	return toSortedSlice(i.all, types)
}

func fromMapped(idMap map[artifact.ID]*mappedRelationships, identifiable artifact.Identifiable) []*sortableRelationship {
	if identifiable == nil || idMap == nil {
		return nil
	}
	mapped := idMap[identifiable.ID()]
	if mapped == nil {
		return nil
	}
	return mapped.allRelated
}

func toSortedSlice(relationships []*sortableRelationship, types []artifact.RelationshipType) []artifact.Relationship {
	// always return sorted for SBOM stability
	slices.SortFunc(relationships, sortFunc)
	var out []artifact.Relationship
	for _, r := range relationships {
		if len(types) == 0 || slices.Contains(types, r.relationship.Type) {
			out = append(out, r.relationship)
		}
	}
	return out
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

type mappedRelationships struct {
	typeMap    map[artifact.RelationshipType]map[artifact.ID]*sortableRelationship
	allRelated []*sortableRelationship
}

func (m *mappedRelationships) add(id artifact.ID, newRelationship *sortableRelationship) {
	m.allRelated = append(m.allRelated, newRelationship)
	if m.typeMap == nil {
		m.typeMap = map[artifact.RelationshipType]map[artifact.ID]*sortableRelationship{}
	}
	typeMap := m.typeMap[newRelationship.relationship.Type]
	if typeMap == nil {
		typeMap = map[artifact.ID]*sortableRelationship{}
		m.typeMap[newRelationship.relationship.Type] = typeMap
	}
	typeMap[id] = newRelationship
}

type sortableRelationship struct {
	from         artifact.ID
	to           artifact.ID
	relationship artifact.Relationship
}

func sortFunc(a, b *sortableRelationship) int {
	cmp := strings.Compare(string(a.relationship.Type), string(b.relationship.Type))
	if cmp != 0 {
		return cmp
	}
	cmp = strings.Compare(string(a.from), string(b.from))
	if cmp != 0 {
		return cmp
	}
	return strings.Compare(string(a.to), string(b.to))
}
