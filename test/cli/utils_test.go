package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

func getFixtureImage(t testing.TB, fixtureImageName string) string {
	imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	return imagetest.GetFixtureImageTarPath(t, fixtureImageName)
}

func runSyftCommand(t testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	cmd := getSyftCommand(t, args...)
	if env != nil {
		var envList []string
		for key, val := range env {
			if key == "" {
				continue
			}
			envList = append(envList, fmt.Sprintf("%s=%s", key, val))
		}
		cmd.Env = envList
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	cmd.Run()

	return cmd, stdout.String(), stderr.String()
}

func getSyftCommand(t testing.TB, args ...string) *exec.Cmd {

	var binaryLocation string
	if os.Getenv("SYFT_BINARY_LOCATION") != "" {
		// SYFT_BINARY_LOCATION is the absolute path to the snapshot binary
		binaryLocation = os.Getenv("SYFT_BINARY_LOCATION")
	} else {
		// note: there is a subtle - vs _ difference between these versions
		switch runtime.GOOS {
		case "darwin":
			binaryLocation = path.Join(repoRoot(t), fmt.Sprintf("snapshot/syft-macos_darwin_%s/syft", runtime.GOARCH))
		case "linux":
			binaryLocation = path.Join(repoRoot(t), fmt.Sprintf("snapshot/syft_linux_%s/syft", runtime.GOARCH))
		default:
			t.Fatalf("unsupported OS: %s", runtime.GOOS)
		}

	}

	return exec.Command(binaryLocation, args...)
}

func repoRoot(t testing.TB) string {
	t.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		t.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}
