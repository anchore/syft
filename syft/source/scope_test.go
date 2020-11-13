package source

import (
	"fmt"
	"testing"
)

func TestOptionStringerBoundary(t *testing.T) {
	var _ fmt.Stringer = Scope(0)

	for _, c := range []int{-1, 0, 3} {
		option := Scope(c)
		if option.String() != UnknownScope.String() {
			t.Errorf("expected Scope(%d) to be unknown, found '%+v'", c, option)
		}
	}
}
