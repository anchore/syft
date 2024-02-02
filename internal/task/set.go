package task

type set struct {
	order []string
	tasks map[string]Task
}

func newSet(tasks ...Task) *set {
	s := &set{
		order: []string{},
		tasks: make(map[string]Task),
	}

	s.Add(tasks...)

	return s
}

func (ts *set) Len() int {
	return len(ts.tasks)
}

func (ts *set) Add(tasks ...Task) {
	for _, t := range tasks {
		taskName := t.Name()
		if _, exists := ts.tasks[taskName]; exists {
			continue
		}
		ts.tasks[taskName] = t
		ts.order = append(ts.order, taskName)
	}
}

func (ts *set) Remove(tasks ...Task) {
	for _, t := range tasks {
		taskName := t.Name()
		if _, exists := ts.tasks[taskName]; !exists {
			continue
		}

		delete(ts.tasks, taskName)
		for i, t := range ts.order {
			if t == taskName {
				ts.order = append(ts.order[:i], ts.order[i+1:]...)
				break
			}
		}
	}
}

func (ts *set) Intersect(tasks ...Task) {
	other := newSet(tasks...)
	result := newSet()
	for _, taskName := range ts.order {
		// we make a new set to prevent the original set from being modified while we are iterating over "order"
		if _, exists := other.tasks[taskName]; exists {
			// note: keep the original task and ordering
			result.Add(ts.tasks[taskName])
		}
	}
	*ts = *result
}

func (ts set) Tasks() tasks {
	var result []Task
	for _, name := range ts.order {
		result = append(result, ts.tasks[name])
	}
	return result
}
