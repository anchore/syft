package syft

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMaybeReduceGOMAXPROCS exercises the GOMAXPROCS alignment guard added
// alongside parallelism configuration; see issue #3924.
func TestMaybeReduceGOMAXPROCS(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(original)
	})

	tests := []struct {
		name        string
		startProcs  int
		parallelism int
		wantProcs   int
	}{
		{
			name:        "default parallelism leaves GOMAXPROCS alone",
			startProcs:  4,
			parallelism: 0,
			wantProcs:   4,
		},
		{
			name:        "serial parallelism leaves GOMAXPROCS alone",
			startProcs:  4,
			parallelism: 1,
			wantProcs:   4,
		},
		{
			name:        "unbounded parallelism leaves GOMAXPROCS alone",
			startProcs:  4,
			parallelism: -1,
			wantProcs:   4,
		},
		{
			name:        "test sentinel leaves GOMAXPROCS alone",
			startProcs:  4,
			parallelism: -99,
			wantProcs:   4,
		},
		{
			name:        "explicit lower parallelism reduces GOMAXPROCS",
			startProcs:  8,
			parallelism: 2,
			wantProcs:   2,
		},
		{
			name:        "parallelism equal to current GOMAXPROCS is a no-op",
			startProcs:  4,
			parallelism: 4,
			wantProcs:   4,
		},
		{
			name:        "parallelism above current GOMAXPROCS does not raise it",
			startProcs:  2,
			parallelism: 16,
			wantProcs:   2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GOMAXPROCS(tc.startProcs)
			maybeReduceGOMAXPROCS(tc.parallelism)
			assert.Equal(t, tc.wantProcs, runtime.GOMAXPROCS(0))
		})
	}
}
