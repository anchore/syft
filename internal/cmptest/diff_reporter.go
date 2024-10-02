package cmptest

import (
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
)

// DiffReporter is a simple custom reporter that only records differences detected during comparison.
type DiffReporter struct {
	path  cmp.Path
	diffs []string
}

func NewDiffReporter() DiffReporter {
	return DiffReporter{}
}

func (r *DiffReporter) PushStep(ps cmp.PathStep) {
	r.path = append(r.path, ps)
}

func (r *DiffReporter) Report(rs cmp.Result) {
	if !rs.Equal() {
		vx, vy := r.path.Last().Values()
		r.diffs = append(r.diffs, fmt.Sprintf("%#v:\n\t-: %+v\n\t+: %+v\n", r.path, vx, vy))
	}
}

func (r *DiffReporter) PopStep() {
	r.path = r.path[:len(r.path)-1]
}

func (r *DiffReporter) String() string {
	return strings.Join(r.diffs, "\n")
}
