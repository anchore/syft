package relationship

import (
	"slices"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

// Index provides an indexed set of relationships for easy location and comparison
type Index struct {
	all      []*sortableRelationship
	byFromID map[artifact.ID]*mapped
	byToID   map[artifact.ID]*mapped
}

// NewIndex returns a new relationship Index
func NewIndex(relationships ...artifact.Relationship) *Index {
	out := Index{}
	out.Add(relationships...)
	return &out
}

// Add adds all the given relationships to the index, without adding duplicates
func (i *Index) Add(relationships ...artifact.Relationship) {
	if i.byFromID == nil {
		i.byFromID = map[artifact.ID]*mapped{}
	}
	if i.byToID == nil {
		i.byToID = map[artifact.ID]*mapped{}
	}

	// store appropriate indexes for stable ordering to minimize ID() calls
	for _, r := range relationships {
		// prevent duplicates
		if i.Contains(r) {
			continue
		}

		fromID := r.From.ID()
		toID := r.To.ID()

		m := i.byFromID[fromID]
		if m == nil {
			m = &mapped{}
			i.byFromID[fromID] = m
		}
		sortableFrom := &sortableRelationship{
			from: fromID,
			to:   toID,
			rel:  r,
		}

		// add to all relationships
		i.all = append(i.all, sortableFrom)

		// add to from -> to mapping
		m.add(toID, sortableFrom)

		m = i.byToID[toID]
		if m == nil {
			m = &mapped{}
			i.byToID[toID] = m
		}

		// add to the to -> from mapping
		m.add(fromID, sortableFrom)
	}
}

// From returns all relationships from the given identifiable, with specified types
func (i *Index) From(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return fromMapped(i.byFromID, identifiable, types)
}

// To returns all relationships to the given identifiable, with specified types
func (i *Index) To(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return fromMapped(i.byToID, identifiable, types)
}

// References returns all relationships that references to or from the given identifiable
func (i *Index) References(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []artifact.Relationship {
	return append(i.To(identifiable, types...), i.From(identifiable, types...)...)
}

// Coordinates returns all coordinates for the provided identifiable for provided relationship types
// If no types are provided, all relationship types are considered.
func (i *Index) Coordinates(identifiable artifact.Identifiable, types ...artifact.RelationshipType) []file.Coordinates {
	var coordinates []file.Coordinates
	for _, relationship := range append(i.To(identifiable, types...), i.From(identifiable, types...)...) {
		cords := extractCoordinates(relationship)
		coordinates = append(coordinates, cords...)
	}
	return coordinates
}

// Contains indicates the relationship is present in this index
func (i *Index) Contains(r artifact.Relationship) bool {
	if m := i.byFromID[r.From.ID()]; m != nil {
		if ids := m.types[(r.Type)]; ids != nil {
			return ids[(r.To.ID())] != nil
		}
	}
	return false
}

// All returns a sorted set of relationships matching all types, or all relationships if no types specified
func (i *Index) All(types ...artifact.RelationshipType) []artifact.Relationship {
	return collect(i.all, types)
}

func fromMapped(mappedIDs map[artifact.ID]*mapped, identifiable artifact.Identifiable, types []artifact.RelationshipType) []artifact.Relationship {
	if identifiable == nil {
		return nil
	}
	m := mappedIDs[identifiable.ID()]
	if m == nil {
		return nil
	}
	return collect(m.rels, types)
}

func collect(rels []*sortableRelationship, types []artifact.RelationshipType) []artifact.Relationship {
	// always return sorted lists for SBOM stability; the sorting could be handled elsewhere
	slices.SortFunc(rels, sortFunc)
	var out []artifact.Relationship
	for _, r := range rels {
		if len(types) == 0 || slices.Contains(types, r.rel.Type) {
			out = append(out, r.rel)
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

type sortableRelationship struct {
	from artifact.ID
	to   artifact.ID
	rel  artifact.Relationship
}

func sortFunc(a, b *sortableRelationship) int {
	cmp := strings.Compare(string(a.rel.Type), string(b.rel.Type))
	if cmp != 0 {
		return cmp
	}
	cmp = strings.Compare(string(a.from), string(b.from))
	if cmp != 0 {
		return cmp
	}
	return strings.Compare(string(a.to), string(b.to))
}

type mapped struct {
	types map[artifact.RelationshipType]map[artifact.ID]*sortableRelationship
	rels  []*sortableRelationship
}

func (m *mapped) add(id artifact.ID, r *sortableRelationship) {
	m.rels = append(m.rels, r)
	if m.types == nil {
		m.types = map[artifact.RelationshipType]map[artifact.ID]*sortableRelationship{}
	}
	tm := m.types[(r.rel.Type)]
	if tm == nil {
		tm = map[artifact.ID]*sortableRelationship{}
		m.types[(r.rel.Type)] = tm
	}
	tm[id] = r
}
