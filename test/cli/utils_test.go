package cli

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/stretchr/testify/require"
)

func setupPKI(t *testing.T, pw string) func() {
	err := os.Setenv("COSIGN_PASSWORD", pw)
	if err != nil {
		t.Fatal(err)
	}

	cosignPath := filepath.Join(repoRoot(t), ".tmp/cosign")
	cmd := exec.Command(cosignPath, "generate-key-pair")
	stdout, stderr, _ := runCommand(cmd, nil)
	if cmd.ProcessState.ExitCode() != 0 {
		t.Log("STDOUT", stdout)
		t.Log("STDERR", stderr)
		t.Fatalf("could not generate keypair")
	}

	return func() {
		err := os.Unsetenv("COSIGN_PASSWORD")
		if err != nil {
			t.Fatal(err)
		}

		err = os.Remove("cosign.key")
		if err != nil {
			t.Fatalf("could not cleanup cosign.key")
		}

		err = os.Remove("cosign.pub")
		if err != nil {
			t.Fatalf("could not cleanup cosign.key")
		}
	}
}

func getFixtureImage(t testing.TB, fixtureImageName string) string {
	t.Logf("obtaining fixture image for %s", fixtureImageName)
	request := imagetest.PrepareFixtureImage(t, "docker-archive", fixtureImageName)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	i, err := stereoscope.GetImage(ctx, request)
	t.Logf("got image %s: %s", fixtureImageName, i.Metadata.ID)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, i.Cleanup())
	})

	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
	t.Logf("returning %s: %s", fixtureImageName, tarPath)
	return tarPath
}

func pullDockerImage(t testing.TB, image string) {
	cmd := exec.Command("docker", "pull", image)
	stdout, stderr, _ := runCommand(cmd, nil)
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
	stdout, stderr, _ := runCommand(cmd, env)
	return cmd, stdout, stderr
}

func runSyft(t testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	return runSyftCommand(t, env, true, args...)
}

func runSyftSafe(t testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	return runSyftCommand(t, env, false, args...)
}

func runSyftCommand(t testing.TB, env map[string]string, expectError bool, args ...string) (*exec.Cmd, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if !expectError {
		args = append(args, "-vv")
	}

	cmd := exec.CommandContext(ctx, getSyftBinaryLocation(t), args...)

	if env == nil {
		env = make(map[string]string)
	}

	// we should not have tests reaching out for app update checks
	env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"

	stdout, stderr, err := runCommand(cmd, env)

	if err != nil && !expectError && stdout == "" {
		fmt.Printf("error running syft: %+v\n", err)
		fmt.Printf("STDOUT: %s\n", stdout)
		fmt.Printf("STDERR: %s\n", stderr)

		// this probably indicates a timeout
		// args = append(args, "-vv")
		cmd = exec.CommandContext(ctx, getSyftBinaryLocation(t), args...)
		stdout, stderr, err = runCommand(cmd, env)

		if err != nil {
			fmt.Printf("error rerunning syft: %+v\n", err)
			fmt.Printf("STDOUT: %s\n", stdout)
			fmt.Printf("STDERR: %s\n", stderr)
		}
	}

	return cmd, stdout, stderr
}

func runCosign(t testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	cmd := getCosignCommand(t, args...)
	if env == nil {
		env = make(map[string]string)
	}

	stdout, stderr, err := runCommand(cmd, env)

	if err != nil {
		fmt.Printf("error running cosign: %+v", err)
	}

	return cmd, stdout, stderr
}

func getCosignCommand(t testing.TB, args ...string) *exec.Cmd {
	return exec.Command(filepath.Join(repoRoot(t), ".tmp/cosign"), args...)
}

func runCommand(cmd *exec.Cmd, env map[string]string) (string, string, error) {
	if env != nil {
		cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	err := cmd.Run()

	return stdout.String(), stderr.String(), err
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

func testRetryIntervals(done <-chan struct{}) <-chan time.Duration {
	return exponentialBackoffDurations(250*time.Millisecond, 4*time.Second, 2, done)
}

func exponentialBackoffDurations(minDuration, maxDuration time.Duration, step float64, done <-chan struct{}) <-chan time.Duration {
	sleepDurations := make(chan time.Duration)
	go func() {
		defer close(sleepDurations)
	retryLoop:
		for attempt := 0; ; attempt++ {
			duration := exponentialBackoffDuration(minDuration, maxDuration, step, attempt)

			select {
			case sleepDurations <- duration:
				break
			case <-done:
				break retryLoop
			}

			if duration == maxDuration {
				break
			}
		}
	}()
	return sleepDurations
}

func exponentialBackoffDuration(minDuration, maxDuration time.Duration, step float64, attempt int) time.Duration {
	duration := time.Duration(float64(minDuration) * math.Pow(step, float64(attempt)))
	if duration < minDuration {
		return minDuration
	} else if duration > maxDuration {
		return maxDuration
	}
	return duration
}
