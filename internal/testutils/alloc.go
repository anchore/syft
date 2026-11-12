package testutils

import (
	"runtime"
	"testing"
)

// MeasureAlloc reports the bytes allocated while fn ran.
//
// This exists for guards whose whole point is "a small input cannot make us reserve a large buffer".
// Only a byte count states that property: asserting that an error comes back would keep passing if the
// allocation were hoisted above the check, which is the bug these guards were written for.
//
// Two things to know when using it:
//
//   - TotalAlloc is process-wide, so a test calling this must not call t.Parallel. Another test's
//     allocations would land in the measurement.
//   - a budget assertion is only meaningful if the fixture would really blow past it unguarded. Prefer
//     measuring the unguarded path too and asserting it exceeds the declared size, so a fixture that
//     quietly stops being a bomb fails instead of passing.
func MeasureAlloc(t testing.TB, fn func()) uint64 {
	t.Helper()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc
}
