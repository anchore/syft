package main

import (
	"os"
	"testing"
)

// checkCompletenessTestsEnabled skips the test if completeness tests are not enabled via environment variable.
// Why do this at all? Can't we just run these tests all the time? Short answer: No.
// These tests are coupled with unit tests under ./syft/pkg/..., which means that these tests must be run not only
// after those unit tests, but also after code generation that reads observations from test results.
// This means that we should not really consider these tests as part of normal unit test runs, but rather as a separate
// self-consistency check during generation, and it's really static analysis that should be checking
// if the generated code has drifted (not a unit test).
func checkCompletenessTestsEnabled(t *testing.T) {
	enabled := os.Getenv("SYFT_ENABLE_COMPLETENESS_TESTS") == "true"
	if !enabled {
		t.Skip("skipping completeness tests (SYFT_ENABLE_COMPLETENESS_TESTS is not set to 'true')")
	}
}
