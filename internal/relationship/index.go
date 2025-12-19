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
	out := Index{
		fromID: make(map[artifact.ID]*mappedRelationships),
		toID:   make(map[artifact.ID]*mappedRelationships),
	}
	out.Add(relationships...)
	return &out
}

// Add adds all the given relationships to the index, without adding duplicates
func (i *Index) Add(relationships ...artifact.Relationship) {
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

func (i *Index) Remove(id artifact.ID) {
	delete(i.fromID, id)
	delete(i.toID, id)

	for idx := 0; idx < len(i.all); {
		if i.all[idx].from == id || i.all[idx].to == id {
			i.all = append(i.all[:idx], i.all[idx+1:]...)
		} else {
			idx++
		}
	}
}

func (i *Index) Replace(ogID artifact.ID, replacement artifact.Identifiable) {
	for _, mapped := range fromMappedByID(i.fromID, ogID) {
		// the stale relationship(i.e. if there's an elder ID in either side) should be discarded
		if len(fromMappedByID(i.toID, mapped.relationship.To.ID())) == 0 {
			continue
		}
		i.Add(artifact.Relationship{
			From: replacement,
			To:   mapped.relationship.To,
			Type: mapped.relationship.Type,
		})
	}

	for _, mapped := range fromMappedByID(i.toID, ogID) {
		// same as the above
		if len(fromMappedByID(i.fromID, mapped.relationship.To.ID())) == 0 {
			continue
		}
		i.Add(artifact.Relationship{
			From: mapped.relationship.From,
			To:   replacement,
			Type: mapped.relationship.Type,
		})
	}

	i.Remove(ogID)
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
	if identifiable == nil {
		return nil
	}
	return fromMappedByID(idMap, identifiable.ID())
}

func fromMappedByID(idMap map[artifact.ID]*mappedRelationships, id artifact.ID) []*sortableRelationship {
	if idMap == nil {
		return nil
	}
	mapped := idMap[id]
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
