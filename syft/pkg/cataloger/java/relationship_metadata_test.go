package java

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDependencyRelationshipData_DirectDependency(t *testing.T) {
	data := NewDependencyRelationshipData(0, "compile")
	assert.Equal(t, 0, data.Depth)
	assert.Equal(t, "compile", data.Scope)
	assert.True(t, data.IsDirectDependency)
	assert.Empty(t, data.IntendedParentID)
}

func TestNewDependencyRelationshipData_TransitiveDependency(t *testing.T) {
	data := NewDependencyRelationshipData(1, "runtime")
	assert.Equal(t, 1, data.Depth)
	assert.Equal(t, "runtime", data.Scope)
	assert.False(t, data.IsDirectDependency)
	assert.Empty(t, data.IntendedParentID)
}

func TestNewDependencyRelationshipData_DeepTransitive(t *testing.T) {
	data := NewDependencyRelationshipData(5, "test")
	assert.Equal(t, 5, data.Depth)
	assert.Equal(t, "test", data.Scope)
	assert.False(t, data.IsDirectDependency)
}

func TestNewDependencyRelationshipDataWithParent(t *testing.T) {
	data := NewDependencyRelationshipDataWithParent(2, "compile", "org.springframework:spring-core:5.3.0")
	assert.Equal(t, 2, data.Depth)
	assert.Equal(t, "compile", data.Scope)
	assert.False(t, data.IsDirectDependency)
	assert.Equal(t, "org.springframework:spring-core:5.3.0", data.IntendedParentID)
}

func TestNewDependencyRelationshipDataWithParent_DirectWithParent(t *testing.T) {
	data := NewDependencyRelationshipDataWithParent(0, "compile", "com.example:root:1.0")
	assert.True(t, data.IsDirectDependency)
	assert.Equal(t, "com.example:root:1.0", data.IntendedParentID)
}

func TestDependencyRelationshipData_ZeroValue(t *testing.T) {
	var data DependencyRelationshipData
	assert.Equal(t, 0, data.Depth)
	assert.Empty(t, data.Scope)
	assert.False(t, data.IsDirectDependency)
	assert.Empty(t, data.IntendedParentID)
}

func TestNewDependencyRelationshipData_EmptyScope(t *testing.T) {
	data := NewDependencyRelationshipData(0, "")
	assert.True(t, data.IsDirectDependency)
	assert.Empty(t, data.Scope)
}
