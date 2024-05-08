package binary

import (
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/artifact"
)

type relationshipIndex struct {
	typesByFromTo map[artifact.ID]map[artifact.ID]*strset.Set
	additional    []artifact.Relationship
}

func newRelationshipIndex(existing ...artifact.Relationship) *relationshipIndex {
	r := &relationshipIndex{
		typesByFromTo: make(map[artifact.ID]map[artifact.ID]*strset.Set),
		additional:    make([]artifact.Relationship, 0),
	}
	for _, rel := range existing {
		r.track(rel)
	}
	return r
}

// track this relationship as "exists" in the index (this is used to prevent duplicate relationships from being added).
// returns true if the relationship is new to the index, false otherwise.
func (i *relationshipIndex) track(r artifact.Relationship) bool {
	fromID := r.From.ID()
	if _, ok := i.typesByFromTo[fromID]; !ok {
		i.typesByFromTo[fromID] = make(map[artifact.ID]*strset.Set)
	}

	toID := r.To.ID()
	if _, ok := i.typesByFromTo[fromID][toID]; !ok {
		i.typesByFromTo[fromID][toID] = strset.New()
	}

	var exists bool
	if i.typesByFromTo[fromID][toID].Has(string(r.Type)) {
		exists = true
	}

	i.typesByFromTo[fromID][toID].Add(string(r.Type))
	return !exists
}

// add a new relationship to the index, returning true if the relationship is new to the index, false otherwise (thus is a duplicate).
// nolint:unparam
func (i *relationshipIndex) add(r artifact.Relationship) bool {
	if i.track(r) {
		i.additional = append(i.additional, r)
		return true
	}
	return false
}

func (i *relationshipIndex) newRelationships() []artifact.Relationship {
	return i.additional
}
