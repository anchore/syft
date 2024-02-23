package testutil

import (
	"os"
	"testing"
)

func Chdir(t *testing.T, dir string) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to get working directory: %v", err)
	}

	err = os.Chdir(dir)
	if err != nil {
		t.Fatalf("unable to chdir to '%s': %v", dir, err)
	}

	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})
}
