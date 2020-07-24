package scope

import (
	"fmt"
	"testing"
)

func TestOptionStringerBoundary(t *testing.T) {
	var _ fmt.Stringer = Option(0)

	for _, c := range []int{-1, 0, 3} {
		option := Option(c)
		if option.String() != UnknownScope.String() {
			t.Errorf("expected Option(%d) to be unknown, found '%+v'", c, option)
		}
	}
}
