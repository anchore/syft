package model

import (
	"testing"
)

func TestAppendChild(t *testing.T) {
	parent := &DepGraphNode{
		Name: "Parent",
	}

	child := &DepGraphNode{
		Name: "Child",
	}

	parent.AppendChild(child)

	// Check if child was added to parent's children
	if len(parent.Children) != 1 || parent.Children[0] != child {
		t.Errorf("Expected child to be added to parent's Children")
	}

	// Check if parent was added to child's parents
	if len(child.Parents) != 1 || child.Parents[0] != parent {
		t.Errorf("Expected parent to be added to child's Parents")
	}

	// Test idempotency - appending child to parent again
	parent.AppendChild(child)

	// Check if child was not added again to parent's children
	if len(parent.Children) != 1 {
		t.Errorf("Expected child not to be added again to parent's Children")
	}

	// Check if parent was not added again to child's parents
	if len(child.Parents) != 1 {
		t.Errorf("Expected parent not to be added again to child's Parents")
	}

	// Test nil cases
	var nilDep *DepGraphNode
	parent.AppendChild(nilDep)
	nilDep.AppendChild(child)
	nilDep.AppendChild(nilDep)

	if len(parent.Children) != 1 || len(child.Parents) != 1 {
		t.Errorf("Nil checks failed. Nil children or parents should not be added.")
	}
}

func TestRemoveChild(t *testing.T) {
	parent := &DepGraphNode{Name: "Parent"}
	child1 := &DepGraphNode{Name: "Child1"}
	child2 := &DepGraphNode{Name: "Child2"}

	// Append children and remove child1
	parent.AppendChild(child1)
	parent.AppendChild(child2)
	parent.RemoveChild(child1)

	// Verify child1 removal and child2 intact
	if len(parent.Children) != 1 || parent.Children[0] != child2 || len(child1.Parents) != 0 {
		t.Errorf("Child1 removal failed or child2 was affected")
	}

	// Double remove check
	parent.RemoveChild(child1)
	if len(parent.Children) != 1 || parent.Children[0] != child2 {
		t.Errorf("Repeated removal affected list")
	}

	// Remove non-appended child
	child3 := &DepGraphNode{Name: "Child3"}
	parent.RemoveChild(child3)

	if len(parent.Children) != 1 || parent.Children[0] != child2 {
		t.Errorf("State affected by invalid remove operations")
	}
}
