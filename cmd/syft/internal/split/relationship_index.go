package split

import (
	"slices"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

// relationshipIndex indexes relationships for efficient lookup by from/to IDs.
// This is a simplified version tailored for the split functionality.
type relationshipIndex struct {
	relationships []*sortableRelationship
	fromID        map[artifact.ID]*mappedRelationships
	toID          map[artifact.ID]*mappedRelationships
}

// newRelationshipIndex creates a new relationship index from the given relationships
func newRelationshipIndex(relationships ...artifact.Relationship) *relationshipIndex {
	idx := &relationshipIndex{
		fromID: make(map[artifact.ID]*mappedRelationships),
		toID:   make(map[artifact.ID]*mappedRelationships),
	}

	for _, r := range relationships {
		// prevent duplicates
		if idx.contains(r) {
			continue
		}

		fromID := r.From.ID()
		toID := r.To.ID()

		sr := &sortableRelationship{
			from:         fromID,
			to:           toID,
			relationship: r,
		}

		idx.relationships = append(idx.relationships, sr)

		// add from -> to mapping
		if idx.fromID[fromID] == nil {
			idx.fromID[fromID] = &mappedRelationships{}
		}
		idx.fromID[fromID].add(toID, sr)

		// add to -> from mapping
		if idx.toID[toID] == nil {
			idx.toID[toID] = &mappedRelationships{}
		}
		idx.toID[toID].add(fromID, sr)
	}

	return idx
}

// from returns all relationships from the given identifiable, filtered by types
func (i *relationshipIndex) from(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return toSortedSlice(fromMapped(i.fromID, identifiable), types)
}

// to returns all relationships to the given identifiable, filtered by types
func (i *relationshipIndex) to(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return toSortedSlice(fromMapped(i.toID, identifiable), types)
}

// coordinates returns all file coordinates referenced by relationships for the given identifiable
func (i *relationshipIndex) coordinates(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []file.Coordinates {
	// get relationships in both directions
	rels := append(fromMapped(i.fromID, identifiable), fromMapped(i.toID, identifiable)...)
	sorted := toSortedSlice(rels, types)

	var coords []file.Coordinates
	for _, rel := range sorted {
		if c, ok := rel.From.(file.Coordinates); ok {
			coords = append(coords, c)
		}
		if c, ok := rel.To.(file.Coordinates); ok {
			coords = append(coords, c)
		}
	}
	return coords
}

// all returns all relationships, optionally filtered by types
func (i *relationshipIndex) all(types ...artifact.RelationshipType) []artifact.Relationship {
	return toSortedSlice(i.relationships, types)
}

// contains checks if the relationship is already in the index
func (i *relationshipIndex) contains(r artifact.Relationship) bool {
	mapped := i.fromID[r.From.ID()]
	if mapped == nil {
		return false
	}
	typeMap := mapped.typeMap[r.Type]
	if typeMap == nil {
		return false
	}
	return typeMap[r.To.ID()] != nil
}

type mappedRelationships struct {
	typeMap    map[artifact.RelationshipType]map[artifact.ID]*sortableRelationship
	allRelated []*sortableRelationship
}

func (m *mappedRelationships) add(id artifact.ID, sr *sortableRelationship) {
	m.allRelated = append(m.allRelated, sr)
	if m.typeMap == nil {
		m.typeMap = make(map[artifact.RelationshipType]map[artifact.ID]*sortableRelationship)
	}
	if m.typeMap[sr.relationship.Type] == nil {
		m.typeMap[sr.relationship.Type] = make(map[artifact.ID]*sortableRelationship)
	}
	m.typeMap[sr.relationship.Type][id] = sr
}

type sortableRelationship struct {
	from         artifact.ID
	to           artifact.ID
	relationship artifact.Relationship
}

func fromMapped(idMap map[artifact.ID]*mappedRelationships, identifiable artifact.Identifiable) []*sortableRelationship {
	if identifiable == nil {
		return nil
	}
	mapped := idMap[identifiable.ID()]
	if mapped == nil {
		return nil
	}
	return mapped.allRelated
}

func toSortedSlice(relationships []*sortableRelationship, types []artifact.RelationshipType) []artifact.Relationship {
	slices.SortFunc(relationships, func(a, b *sortableRelationship) int {
		cmp := strings.Compare(string(a.relationship.Type), string(b.relationship.Type))
		if cmp != 0 {
			return cmp
		}
		cmp = strings.Compare(string(a.from), string(b.from))
		if cmp != 0 {
			return cmp
		}
		return strings.Compare(string(a.to), string(b.to))
	})

	var out []artifact.Relationship
	for _, r := range relationships {
		if len(types) == 0 || slices.Contains(types, r.relationship.Type) {
			out = append(out, r.relationship)
		}
	}
	return out
}
