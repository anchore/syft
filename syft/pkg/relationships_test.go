package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
)

func TestSortRelationships(t *testing.T) {
	tests := []struct {
		name     string
		input    []artifact.Relationship
		expected []artifact.Relationship
	}{
		{
			name: "basic sort",
			input: []artifact.Relationship{
				{
					From: &Package{Name: "test-app", Version: "0.0.0"},
					To:   &Package{Name: "tslib", Version: "2.4.1"},
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: &Package{Name: "test-app", Version: "0.0.0"},
					To:   &Package{Name: "zone.js", Version: "0.11.8"},
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: &Package{Name: "test-app", Version: "0.0.0"},
					To:   &Package{Name: "rxjs", Version: "7.5.7"},
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: &Package{Name: "test-app", Version: "0.0.0"},
					To:   &Package{Name: "typescript", Version: "4.7.4"},
					Type: artifact.DependencyOfRelationship,
				},
			},
			expected: []artifact.Relationship{
				{
					From: &Package{Name: "test-app", Version: "0.0.0"},
					To:   &Package{Name: "rxjs", Version: "7.5.7"},
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: &Package{Name: "test-app", Version: "0.0.0"},
					To:   &Package{Name: "tslib", Version: "2.4.1"},
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: &Package{Name: "test-app", Version: "0.0.0"},
					To:   &Package{Name: "typescript", Version: "4.7.4"},
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: &Package{Name: "test-app", Version: "0.0.0"},
					To:   &Package{Name: "zone.js", Version: "0.11.8"},
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: &Package{Name: "zone.js", Version: "0.11.8"},
					To:   &Package{Name: "rxjs", Version: "7.5.7"},
					Type: artifact.DependencyOfRelationship,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SortRelationships(tt.input)
			for i, got := range tt.input {
				if !compareRelationships(got, tt.expected[i]) {
					t.Errorf("Expected %v, got %v", tt.expected[i], got)
				}
			}
		})
	}
}

func compareRelationships(a, b artifact.Relationship) bool {
	aFrom, ok1 := a.From.(*Package)
	bFrom, ok2 := b.From.(*Package)
	aTo, ok3 := a.To.(*Package)
	bTo, ok4 := b.To.(*Package)

	if !(ok1 && ok2 && ok3 && ok4) {
		return false
	}

	return aFrom.Name == bFrom.Name &&
		aFrom.Version == bFrom.Version &&
		aTo.Name == bTo.Name &&
		aTo.Version == bTo.Version &&
		a.Type == b.Type
}
