package binary

import (
	"reflect"
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/artifact"
)

func Test_newRelationshipIndex(t *testing.T) {
	from := fakeIdentifiable{id: "from"}
	to := fakeIdentifiable{id: "to"}
	tests := []struct {
		name  string
		given []artifact.Relationship
		want  *relationshipIndex
	}{
		{
			name: "newRelationshipIndex returns an empty index with no existing relationships",
			want: &relationshipIndex{
				typesByFromTo: make(map[artifact.ID]map[artifact.ID]*strset.Set),
				additional:    make([]artifact.Relationship, 0),
			},
		},
		{
			name: "newRelationshipIndex returns an index which tracks existing relationships",
			given: []artifact.Relationship{
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
			},
			want: &relationshipIndex{
				typesByFromTo: map[artifact.ID]map[artifact.ID]*strset.Set{
					"from": {
						"to": strset.New("evident-by"),
					},
				},
				additional: make([]artifact.Relationship, 0),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newRelationshipIndex(tt.given...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newRelationshipIndex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_relationshipIndex_track(t *testing.T) {
	from := fakeIdentifiable{id: "from"}
	to := fakeIdentifiable{id: "to"}
	relationship := artifact.Relationship{From: from, To: to, Type: artifact.EvidentByRelationship}
	tests := []struct {
		name     string
		existing []artifact.Relationship
		given    artifact.Relationship
		want     bool
	}{
		{
			name:     "track returns true for a new relationship",
			existing: []artifact.Relationship{},
			given:    relationship,
			want:     true,
		},
		{
			name:     "track returns false for an existing relationship",
			existing: []artifact.Relationship{relationship},
			given:    relationship,
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := newRelationshipIndex(tt.existing...)
			if got := i.track(tt.given); got != tt.want {
				t.Errorf("track() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_relationshipIndex_add(t *testing.T) {
	from := fakeIdentifiable{id: "from"}
	to := fakeIdentifiable{id: "to"}
	relationship := artifact.Relationship{From: from, To: to, Type: artifact.EvidentByRelationship}
	tests := []struct {
		name     string
		existing []artifact.Relationship
		given    artifact.Relationship
		want     bool
	}{
		{
			name:     "add returns true for a new relationship",
			existing: []artifact.Relationship{},
			given:    relationship,
			want:     true,
		},
		{
			name:     "add returns false for an existing relationship",
			existing: []artifact.Relationship{relationship},
			given:    relationship,
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := newRelationshipIndex(tt.existing...)
			if got := i.add(tt.given); got != tt.want {
				t.Errorf("add() = %v, want %v", got, tt.want)
			}
		})
	}

}

type fakeIdentifiable struct {
	id string
}

func (f fakeIdentifiable) ID() artifact.ID {
	return artifact.ID(f.id)
}
