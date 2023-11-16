package packagemetadata

import (
	"reflect"
	"testing"
)

type CompletionTester struct {
	saw    []any
	valid  []any
	ignore []any
}

func NewCompletionTester(t testing.TB, ignore ...any) *CompletionTester {
	tester := &CompletionTester{
		valid:  AllTypes(),
		ignore: ignore,
	}
	t.Cleanup(func() {
		t.Helper()
		tester.validate(t)
	})
	return tester
}

func (tr *CompletionTester) Tested(t testing.TB, m any) {
	t.Helper()

	if m == nil {
		return
	}
	if len(tr.valid) == 0 {
		t.Fatal("no valid metadata types to test against")
	}
	ty := reflect.TypeOf(m)
	for _, v := range tr.valid {
		if reflect.TypeOf(v) == ty {
			tr.saw = append(tr.saw, m)
			return
		}
	}

	t.Fatalf("tested metadata type is not valid: %s", ty.Name())
}

func (tr *CompletionTester) validate(t testing.TB) {
	t.Helper()

	count := make(map[reflect.Type]int)
	for _, m := range tr.saw {
		count[reflect.TypeOf(m)]++
	}

validations:
	for _, v := range tr.valid {
		ty := reflect.TypeOf(v)

		for _, ignore := range tr.ignore {
			if ty == reflect.TypeOf(ignore) {
				// skip ignored types
				continue validations
			}
		}

		if c, exists := count[ty]; c == 0 || !exists {
			t.Errorf("metadata type %s is not covered by a test", ty.Name())
		}
	}
}
