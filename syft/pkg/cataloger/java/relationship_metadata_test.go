package java

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDependencyRelationshipData(t *testing.T) {
	tests := []struct {
		name               string
		depth              int
		scope              string
		expectDirect       bool
		expectDepth        int
		expectScope        string
		expectIntendedPart string
	}{
		{
			name:         "direct dependency (depth 0)",
			depth:        0,
			scope:        "compile",
			expectDirect: true,
			expectDepth:  0,
			expectScope:  "compile",
		},
		{
			name:         "transitive dependency (depth 1)",
			depth:        1,
			scope:        "runtime",
			expectDirect: false,
			expectDepth:  1,
			expectScope:  "runtime",
		},
		{
			name:         "deep transitive (depth 3)",
			depth:        3,
			scope:        "",
			expectDirect: false,
			expectDepth:  3,
			expectScope:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := NewDependencyRelationshipData(tt.depth, tt.scope)
			assert.Equal(t, tt.expectDepth, data.Depth)
			assert.Equal(t, tt.expectScope, data.Scope)
			assert.Equal(t, tt.expectDirect, data.IsDirectDependency)
			assert.Empty(t, data.IntendedParentID)
		})
	}
}

func TestNewDependencyRelationshipDataWithParent(t *testing.T) {
	tests := []struct {
		name             string
		depth            int
		scope            string
		intendedParentID string
		expectDirect     bool
	}{
		{
			name:             "direct with deferred parent",
			depth:            0,
			scope:            "compile",
			intendedParentID: "org.example:parent:1.0",
			expectDirect:     true,
		},
		{
			name:             "transitive with deferred parent",
			depth:            2,
			scope:            "test",
			intendedParentID: "org.example:lib-a:2.0",
			expectDirect:     false,
		},
		{
			name:             "empty parent ID",
			depth:            1,
			scope:            "",
			intendedParentID: "",
			expectDirect:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := NewDependencyRelationshipDataWithParent(tt.depth, tt.scope, tt.intendedParentID)
			assert.Equal(t, tt.depth, data.Depth)
			assert.Equal(t, tt.scope, data.Scope)
			assert.Equal(t, tt.expectDirect, data.IsDirectDependency)
			assert.Equal(t, tt.intendedParentID, data.IntendedParentID)
		})
	}
}

func TestDependencyRelationshipData_IntendedParentMavenID(t *testing.T) {
	tests := []struct {
		name     string
		data     DependencyRelationshipData
		expected string
	}{
		{
			name:     "empty intended parent",
			data:     NewDependencyRelationshipData(0, "compile"),
			expected: "",
		},
		{
			name:     "with intended parent",
			data:     NewDependencyRelationshipDataWithParent(1, "runtime", "org.example:lib:1.0"),
			expected: "intendedParent=org.example:lib:1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.data.IntendedParentMavenID())
		})
	}
}
