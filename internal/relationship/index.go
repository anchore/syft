package relationship

import (
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/artifact"
)

type Index struct {
	typesByFromTo map[artifact.ID]map[artifact.ID]*strset.Set
	existing      []artifact.Relationship
	additional    []artifact.Relationship
}

func NewIndex(existing ...artifact.Relationship) *Index {
	r := &Index{
		typesByFromTo: make(map[artifact.ID]map[artifact.ID]*strset.Set),
	}
	r.TrackAll(existing...)
	return r
}

func (i *Index) track(r artifact.Relationship) bool {
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

// Track this relationship as "exists" in the index (this is used to prevent duplicate relationships from being added).
// returns true if the relationship is new to the index, false otherwise.
func (i *Index) Track(r artifact.Relationship) bool {
	unique := i.track(r)
	if unique {
		i.existing = append(i.existing, r)
	}
	return unique
}

// Add a new relationship to the index, returning true if the relationship is new to the index, false otherwise (thus is a duplicate).
func (i *Index) Add(r artifact.Relationship) bool {
	if i.track(r) {
		i.additional = append(i.additional, r)
		return true
	}
	return false
}

func (i *Index) TrackAll(rs ...artifact.Relationship) {
	for _, r := range rs {
		i.Track(r)
	}
}

func (i *Index) AddAll(rs ...artifact.Relationship) {
	for _, r := range rs {
		i.Add(r)
	}
}

func (i *Index) NewRelationships() []artifact.Relationship {
	return i.additional
}

func (i *Index) ExistingRelationships() []artifact.Relationship {
	return i.existing
}

func (i *Index) AllUniqueRelationships() []artifact.Relationship {
	var all []artifact.Relationship
	all = append(all, i.existing...)
	all = append(all, i.additional...)
	return all
}
