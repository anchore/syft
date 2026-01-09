package internal

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepoRoot finds the git repository root directory.
// Exported for use by the generator in generate/main.go
func RepoRoot() (string, error) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		return "", fmt.Errorf("unable to get abs path to repo root: %w", err)
	}
	return absRepoRoot, nil
}
