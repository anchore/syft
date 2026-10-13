package testutils

import (
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var dockerServerOS = sync.OnceValue(func() string {
	out, err := exec.Command("docker", "version", "--format", "{{.Server.Os}}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
})

// SkipWithoutLinuxContainers skips tests whose fixtures are linux container images (built or run via docker).
// This only kicks in on windows, where the docker daemon is often running windows containers (or is absent),
// so the linux fixture images can't be built. Everywhere else the fixture tooling is left to fail loudly.
func SkipWithoutLinuxContainers(t testing.TB) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	if os := dockerServerOS(); os != "linux" {
		t.Skipf("linux container fixtures unavailable (docker server os=%q)", os)
	}
}
