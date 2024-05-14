package task

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
)

var _ Task = (*mockTask)(nil)

type mockTask struct {
	name string
}

func (m mockTask) Execute(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
	panic("implement me")
}

func (m mockTask) Name() string {
	return m.name
}

func Test_set_Add(t *testing.T) {
	tests := []struct {
		name         string
		initialTasks []Task
		newTasks     []Task
		expected     []string
	}{
		{
			name:         "add unique tasks",
			initialTasks: []Task{mockTask{"task2"}, mockTask{"task1"}},
			newTasks:     []Task{mockTask{"task3"}},
			expected: []string{
				"task2", // note order is honored
				"task1",
				"task3",
			},
		},
		{
			name:         "add duplicate tasks",
			initialTasks: []Task{mockTask{"task1"}, mockTask{"task2"}},
			newTasks:     []Task{mockTask{"task1"}},
			expected: []string{
				"task1",
				"task2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSet(tt.initialTasks...)
			s.Add(tt.newTasks...)
			got := s.Tasks()
			var gotNames []string
			for _, tsk := range got {
				gotNames = append(gotNames, tsk.Name())
			}
			assert.Equal(t, tt.expected, gotNames)
		})
	}
}

func Test_set_Remove(t *testing.T) {
	tests := []struct {
		name          string
		initialTasks  []Task
		tasksToRemove []Task
		expectedOrder []string
	}{
		{
			name:          "remove existing tasks",
			initialTasks:  []Task{mockTask{"task1"}, mockTask{"task2"}, mockTask{"task3"}},
			tasksToRemove: []Task{mockTask{"task2"}},
			expectedOrder: []string{"task1", "task3"},
		},
		{
			name:          "remove non-existing tasks",
			initialTasks:  []Task{mockTask{"task1"}, mockTask{"task2"}},
			tasksToRemove: []Task{mockTask{"task3"}},
			expectedOrder: []string{"task1", "task2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSet(tt.initialTasks...)
			s.Remove(tt.tasksToRemove...)
			assert.Equal(t, tt.expectedOrder, s.order)
		})
	}
}

func Test_set_Intersect(t *testing.T) {
	tests := []struct {
		name           string
		initialTasks   []Task
		intersectTasks []Task
		expectedOrder  []string
	}{
		{
			name:           "intersect with overlapping tasks",
			initialTasks:   []Task{mockTask{"task1"}, mockTask{"task2"}},
			intersectTasks: []Task{mockTask{"task2"}, mockTask{"task3"}},
			expectedOrder:  []string{"task2"},
		},
		{
			name:           "intersect with non-overlapping tasks",
			initialTasks:   []Task{mockTask{"task1"}, mockTask{"task4"}},
			intersectTasks: []Task{mockTask{"task2"}, mockTask{"task3"}},
			expectedOrder:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSet(tt.initialTasks...)
			s.Intersect(tt.intersectTasks...)
			assert.Equal(t, tt.expectedOrder, s.order)
		})
	}
}

func Test_set_Tasks(t *testing.T) {
	tests := []struct {
		name          string
		initialTasks  []Task
		expectedTasks tasks
	}{
		{
			name:          "empty set",
			initialTasks:  []Task{},
			expectedTasks: nil,
		},
		{
			name:          "get tasks from set",
			initialTasks:  []Task{mockTask{"task1"}, mockTask{"task2"}},
			expectedTasks: []Task{mockTask{"task1"}, mockTask{"task2"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSet(tt.initialTasks...)
			resultTasks := s.Tasks()
			assert.Equal(t, tt.expectedTasks, resultTasks)
		})
	}
}
