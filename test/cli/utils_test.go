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
	t.Logf("obtaining fixture image for %s", fixtureImageName)
	imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	return imagetest.GetFixtureImageTarPath(t, fixtureImageName)
}

func pullDockerImage(t testing.TB, image string) {
	cmd := exec.Command("docker", "pull", image)
	stdout, stderr := runCommand(cmd, nil)
	if cmd.ProcessState.ExitCode() != 0 {
		t.Log("STDOUT", stdout)
		t.Log("STDERR", stderr)
		t.Fatalf("could not pull docker image")
	}
}

func runSyftInDocker(t testing.TB, env map[string]string, image string, args ...string) (*exec.Cmd, string, string) {
	allArgs := append(
		[]string{
			"run",
			"-t",
			"-e",
			"SYFT_CHECK_FOR_APP_UPDATE=false",
			"-v",
			fmt.Sprintf("%s:/syft", getSyftBinaryLocationByOS(t, "linux")),
			image,
			"/syft",
		},
		args...,
	)
	cmd := exec.Command("docker", allArgs...)
	stdout, stderr := runCommand(cmd, env)
	return cmd, stdout, stderr
}

func runSyft(t testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	cmd := getSyftCommand(t, args...)
	if env == nil {
		env = make(map[string]string)
	}

	// we should not have tests reaching out for app update checks
	env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"

	stdout, stderr := runCommand(cmd, env)
	return cmd, stdout, stderr
}

func runCommand(cmd *exec.Cmd, env map[string]string) (string, string) {
	if env != nil {
		cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	cmd.Run()

	return stdout.String(), stderr.String()
}

func envMapToSlice(env map[string]string) (envList []string) {
	for key, val := range env {
		if key == "" {
			continue
		}
		envList = append(envList, fmt.Sprintf("%s=%s", key, val))
	}
	return
}

func getSyftCommand(t testing.TB, args ...string) *exec.Cmd {
	return exec.Command(getSyftBinaryLocation(t), args...)
}

func getSyftBinaryLocation(t testing.TB) string {
	if os.Getenv("SYFT_BINARY_LOCATION") != "" {
		// SYFT_BINARY_LOCATION is the absolute path to the snapshot binary
		return os.Getenv("SYFT_BINARY_LOCATION")
	}
	return getSyftBinaryLocationByOS(t, runtime.GOOS)
}

func getSyftBinaryLocationByOS(t testing.TB, goOS string) string {
	// note: there is a subtle - vs _ difference between these versions
	switch goOS {
	case "darwin", "linux":
		return path.Join(repoRoot(t), fmt.Sprintf("snapshot/%s-build_%s_%s/syft", goOS, goOS, runtime.GOARCH))
	default:
		t.Fatalf("unsupported OS: %s", runtime.GOOS)
	}
	return ""
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
