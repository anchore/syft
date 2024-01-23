package commands

import (
	"context"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/file"
)

var _ interface {
	task.Task
	task.Selector
} = (*dummyTask)(nil)

type dummyTask struct {
	name      string
	selectors []string
}

func (d dummyTask) HasAllSelectors(s ...string) bool {
	return strset.New(d.selectors...).Has(s...)
}

func (d dummyTask) Selectors() []string {
	return d.selectors
}

func (d dummyTask) Name() string {
	return d.name
}

func (d dummyTask) Execute(_ context.Context, _ file.Resolver, _ sbomsync.Builder) error {
	panic("implement me")
}

func testTasks() []task.Task {
	return []task.Task{
		dummyTask{
			name:      "task1",
			selectors: []string{"image", "a", "b", "1"},
		},
		dummyTask{
			name:      "task2",
			selectors: []string{"image", "b", "c", "2"},
		},
		dummyTask{
			name:      "task3",
			selectors: []string{"directory", "c", "d", "3"},
		},
		dummyTask{
			name:      "task4",
			selectors: []string{"directory", "d", "e", "4"},
		},
	}
}

func Test_catalogerListReport(t *testing.T) {
	tests := []struct {
		name    string
		options *catalogerListOptions
		want    string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "no expressions, table",
			options: func() *catalogerListOptions {
				c := defaultCatalogerListOptions()
				c.Output = "table"
				return c
			}(),
			want: `
Default selections:
  - "all"
┌───────────┬────────────────────┐
│ CATALOGER │ TAGS               │
├───────────┼────────────────────┤
│ task1     │ 1, a, b, image     │
│ task2     │ 2, b, c, image     │
│ task3     │ 3, c, d, directory │
│ task4     │ 4, d, directory, e │
└───────────┴────────────────────┘
`,
		},
		{
			name: "no expressions, json",
			options: func() *catalogerListOptions {
				c := defaultCatalogerListOptions()
				c.Output = "json"
				return c
			}(),
			want: `
{"default":["all"],"selection":[],"catalogers":[{"name":"task1","tags":["1","a","b","image"]},{"name":"task2","tags":["2","b","c","image"]},{"name":"task3","tags":["3","c","d","directory"]},{"name":"task4","tags":["4","d","directory","e"]}]}
`,
		},
		{
			name: "no expressions, default selection, table",
			options: func() *catalogerListOptions {
				c := defaultCatalogerListOptions()
				c.Output = "table"
				c.DefaultCatalogers = []string{
					"image",
				}
				return c
			}(),
			want: `
Default selections:
  - "image"
┌───────────┬────────────────┐
│ CATALOGER │ TAGS           │
├───────────┼────────────────┤
│ task1     │ 1, a, b, image │
│ task2     │ 2, b, c, image │
└───────────┴────────────────┘
`,
		},
		{
			name: "no expressions, default selection, json",
			options: func() *catalogerListOptions {
				c := defaultCatalogerListOptions()
				c.Output = "json"
				c.DefaultCatalogers = []string{
					"image",
				}
				return c
			}(),
			want: `
{"default":["image"],"selection":[],"catalogers":[{"name":"task1","tags":["image"]},{"name":"task2","tags":["image"]}]}
`,
		},
		{
			name: "with expressions, default selection, table",
			options: func() *catalogerListOptions {
				c := defaultCatalogerListOptions()
				c.Output = "table"
				c.DefaultCatalogers = []string{
					"image",
				}
				c.SelectCatalogers = []string{
					"-directory",
					"+task3",
					"-c",
					"b",
				}
				return c
			}(),
			want: `
Default selections:
  - "image"
Selected by expressions:
  - "-directory"
  - "+task3"
  - "-c"
  - "b"
┌───────────┬────────────────────┐
│ CATALOGER │ TAGS               │
├───────────┼────────────────────┤
│ task1     │ 1, a, b, image     │
│ task3     │ 3, c, d, directory │
└───────────┴────────────────────┘
`,
		},
		{
			name: "with expressions, default selection, json",
			options: func() *catalogerListOptions {
				c := defaultCatalogerListOptions()
				c.Output = "json"
				c.DefaultCatalogers = []string{
					"image",
				}
				c.SelectCatalogers = []string{
					"-directory",
					"+task3",
					"-c",
					"b",
				}
				return c
			}(),
			want: `
{"default":["image"],"selection":["-directory","+task3","-c","b"],"catalogers":[{"name":"task1","tags":["b","image"]},{"name":"task3","tags":["task3"]}]}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := catalogerListReport(tt.options, testTasks())
			tt.wantErr(t, err)
			assert.Equal(t, strings.TrimSpace(tt.want), strings.TrimSpace(got))
		})
	}
}
