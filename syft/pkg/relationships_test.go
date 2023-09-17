package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
)

func TestSortRelationships(t *testing.T) {
	rxjs := Package{
		Name:         "rxjs",
		Version:      "7.5.0",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/rxjs@7.5.0",
		Language:     JavaScript,
		Type:         NpmPkg,
		MetadataType: NpmPackageLockJSONMetadataType,
	}
	testApp := Package{
		Name:         "test-app",
		Version:      "0.0.0",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/test-app@0.0.0",
		Language:     JavaScript,
		Type:         NpmPkg,
		MetadataType: NpmPackageLockJSONMetadataType,
	}
	tslib := Package{
		Name:         "tslib",
		Version:      "2.6.2",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/tslib@2.6.2",
		Language:     JavaScript,
		Type:         NpmPkg,
		MetadataType: NpmPackageLockJSONMetadataType,
	}
	typescript := Package{
		Name:         "typescript",
		Version:      "4.7.4",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/typescript@4.7.4",
		Language:     JavaScript,
		Type:         NpmPkg,
		MetadataType: NpmPackageLockJSONMetadataType,
	}
	zonejs := Package{
		Name:         "zone.js",
		Version:      "0.11.8",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/zone.js@0.11.8",
		Language:     JavaScript,
		Type:         NpmPkg,
		MetadataType: NpmPackageLockJSONMetadataType,
	}

	tests := []struct {
		name     string
		input    []artifact.Relationship
		expected []artifact.Relationship
	}{
		{
			name: "basic sort",
			input: []artifact.Relationship{
				{
					From: testApp,
					To:   zonejs,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: testApp,
					To:   rxjs,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: testApp,
					To:   tslib,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: testApp,
					To:   typescript,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: zonejs,
					To:   tslib,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: rxjs,
					To:   tslib,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
			},
			expected: []artifact.Relationship{
				{
					From: rxjs,
					To:   tslib,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: testApp,
					To:   rxjs,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: testApp,
					To:   tslib,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: testApp,
					To:   typescript,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: testApp,
					To:   zonejs,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
				},
				{
					From: zonejs,
					To:   tslib,
					Type: artifact.DependencyOfRelationship,
					Data: nil,
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
	aFrom, ok1 := a.From.(Package)
	bFrom, ok2 := b.From.(Package)
	aTo, ok3 := a.To.(Package)
	bTo, ok4 := b.To.(Package)

	if !(ok1 && ok2 && ok3 && ok4) {
		return false
	}

	return aFrom.Name == bFrom.Name &&
		aFrom.Version == bFrom.Version &&
		aTo.Name == bTo.Name &&
		aTo.Version == bTo.Version &&
		a.Type == b.Type
}
