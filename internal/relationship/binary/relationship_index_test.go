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

type fakeIdentifiable struct {
	id string
}

func (f fakeIdentifiable) ID() artifact.ID {
	return artifact.ID(f.id)
}
