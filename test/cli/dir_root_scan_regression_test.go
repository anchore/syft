package cli

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDirectoryScanCompletesWithinTimeout(t *testing.T) {

	var cmd *exec.Cmd
	var stdout, stderr string
	done := make(chan struct{})
	go func() {
		defer close(done)
		cmd, stdout, stderr = runSyftInDocker(t, nil, "alpine:latest", "dir:/", "-vv")
	}()

	select {
	case <-done:
		break
	case <-time.After(5 * time.Second):
		t.Fatalf("directory scan is taking too long")
	}

	assertions := []traitAssertion{
		assertTableReport,
		assertSuccessfulReturnCode,
	}

	for _, traitFn := range assertions {
		traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
	}

	if t.Failed() {
		t.Log("STDOUT:\n", stdout)
		t.Log("STDERR:\n", stderr)
		t.Log("COMMAND:", strings.Join(cmd.Args, " "))
	}

}
