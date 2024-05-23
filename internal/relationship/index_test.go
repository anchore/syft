package relationship

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/artifact"
)

func Test_newRelationshipIndex(t *testing.T) {
	from := fakeIdentifiable{id: "from"}
	to := fakeIdentifiable{id: "to"}
	tests := []struct {
		name           string
		given          []artifact.Relationship
		track          []artifact.Relationship
		add            []artifact.Relationship
		wantExisting   []string
		wantAdditional []string
	}{
		{
			name: "empty",
		},
		{
			name: "tracks existing relationships",
			given: []artifact.Relationship{
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
			},
			wantExisting: []string{"from [evident-by] to"},
		},
		{
			name: "deduplicate tracked relationships",
			given: []artifact.Relationship{
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
			},
			track: []artifact.Relationship{
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
			},
			wantExisting: []string{"from [evident-by] to"},
		},
		{
			name: "deduplicate any input relationships",
			given: []artifact.Relationship{
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
			},
			track: []artifact.Relationship{
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
			},
			add: []artifact.Relationship{
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
			},
			wantExisting: []string{"from [evident-by] to"},
		},
		{
			name: "deduplicate any added relationships",
			add: []artifact.Relationship{
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
				{
					From: from,
					To:   to,
					Type: artifact.EvidentByRelationship,
				},
			},
			wantAdditional: []string{"from [evident-by] to"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := NewIndex(tt.given...)
			idx.TrackAll(tt.track...)
			idx.AddAll(tt.add...)
			diffRelationships(t, tt.wantExisting, idx.existing)
			diffRelationships(t, tt.wantAdditional, idx.additional)
		})
	}
}

func diffRelationships(t *testing.T, expected []string, actual []artifact.Relationship) {
	if d := cmp.Diff(expected, stringRelationships(actual)); d != "" {
		t.Errorf("unexpected relationships (-want, +got): %s", d)
	}
}

func stringRelationships(relationships []artifact.Relationship) []string {
	var result []string
	for _, r := range relationships {
		result = append(result, string(r.From.ID())+" ["+string(r.Type)+"] "+string(r.To.ID()))
	}
	return result

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
			i := NewIndex(tt.existing...)
			if got := i.Track(tt.given); got != tt.want {
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
			i := NewIndex(tt.existing...)
			if got := i.Add(tt.given); got != tt.want {
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
