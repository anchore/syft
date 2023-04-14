package cli

import (
	"os/exec"
	"testing"
	"time"
)

func TestDirectoryScanCompletesWithinTimeout(t *testing.T) {
	image := "alpine:latest"

	// we want to pull the image ahead of the test as to not affect the timeout value
	pullDockerImage(t, image)

	var cmd *exec.Cmd
	var stdout, stderr string
	done := make(chan struct{})
	go func() {
		defer close(done)
		cmd, stdout, stderr = runSyftInDocker(t, nil, image, "dir:/", "-vv")
	}()

	select {
	case <-done:
		break
	case <-time.After(10 * time.Second):
		t.Fatalf("directory scan is taking too long")
	}

	assertions := []traitAssertion{
		assertTableReport,
		assertSuccessfulReturnCode,
	}

	for _, traitFn := range assertions {
		traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
	}

	logOutputOnFailure(t, cmd, stdout, stderr)

}
