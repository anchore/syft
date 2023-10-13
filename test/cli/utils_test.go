package cli

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

var showOutput = flag.Bool("show-output", false, "show stdout and stderr for failing tests")

func logOutputOnFailure(t testing.TB, cmd *exec.Cmd, stdout, stderr string) {
	if t.Failed() && showOutput != nil && *showOutput {
		t.Log("STDOUT:\n", stdout)
		t.Log("STDERR:\n", stderr)
		t.Log("COMMAND:", strings.Join(cmd.Args, " "))
	}
}

func getFixtureImage(t testing.TB, fixtureImageName string) string {
	t.Logf("obtaining fixture image for %s", fixtureImageName)
	imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	return imagetest.GetFixtureImageTarPath(t, fixtureImageName)
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

// docker run -v $(pwd)/sbom:/sbom cyclonedx/cyclonedx-cli:latest validate --input-format json --input-version v1_4 --input-file /sbom
func runCycloneDXInDocker(_ testing.TB, env map[string]string, image string, f *os.File, args ...string) (*exec.Cmd, string, string) {
	allArgs := append(
		[]string{
			"run",
			"-t",
			"-v",
			fmt.Sprintf("%s:/sbom", f.Name()),
			image,
		},
		args...,
	)
	cmd := exec.Command("docker", allArgs...)
	stdout, stderr, _ := runCommand(cmd, env)
	return cmd, stdout, stderr
}

func runSyftInDocker(t testing.TB, env map[string]string, image string, args ...string) (*exec.Cmd, string, string) {
	allArgs := append(
		[]string{
			"run",
			"-t",
			"-e",
			"SYFT_CHECK_FOR_APP_UPDATE=false",
			"-v",
			fmt.Sprintf("%s:/syft", getSyftBinaryLocationByOS(t, "linux", runtime.GOARCH)),
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
	cancel := make(chan bool, 1)
	defer func() {
		cancel <- true
	}()

	cmd := getSyftCommand(t, args...)
	if env == nil {
		env = make(map[string]string)
	}

	// we should not have tests reaching out for app update checks
	env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"

	timeout := func() {
		select {
		case <-cancel:
			return
		case <-time.After(60 * time.Second):
		}

		if cmd != nil && cmd.Process != nil {
			// get a stack trace printed
			err := cmd.Process.Signal(syscall.SIGABRT)
			if err != nil {
				t.Errorf("error aborting: %+v", err)
			}
		}
	}

	go timeout()

	stdout, stderr, err := runCommand(cmd, env)

	if !expectError && err != nil && stdout == "" {
		t.Errorf("error running syft: %+v", err)
		t.Errorf("STDOUT: %s", stdout)
		t.Errorf("STDERR: %s", stderr)

		// this probably indicates a timeout... lets run it again with more verbosity to help debug issues
		args = append(args, "-vv")
		cmd = getSyftCommand(t, args...)

		go timeout()
		stdout, stderr, err = runCommand(cmd, env)

		if err != nil {
			t.Errorf("error rerunning syft: %+v", err)
			t.Errorf("STDOUT: %s", stdout)
			t.Errorf("STDERR: %s", stderr)
		}
	}

	return cmd, stdout, stderr
}

func runCommandObj(t testing.TB, cmd *exec.Cmd, env map[string]string, expectError bool) (string, string) {
	cancel := make(chan bool, 1)
	defer func() {
		cancel <- true
	}()

	if env == nil {
		env = make(map[string]string)
	}

	// we should not have tests reaching out for app update checks
	env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"

	timeout := func() {
		select {
		case <-cancel:
			return
		case <-time.After(60 * time.Second):
		}

		if cmd != nil && cmd.Process != nil {
			// get a stack trace printed
			err := cmd.Process.Signal(syscall.SIGABRT)
			if err != nil {
				t.Errorf("error aborting: %+v", err)
			}
		}
	}

	go timeout()

	stdout, stderr, err := runCommand(cmd, env)

	if !expectError && err != nil && stdout == "" {
		t.Errorf("error running syft: %+v", err)
		t.Errorf("STDOUT: %s", stdout)
		t.Errorf("STDERR: %s", stderr)
	}

	return stdout, stderr
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

func getSyftCommand(t testing.TB, args ...string) *exec.Cmd {
	return exec.Command(getSyftBinaryLocation(t), args...)
}

func getSyftBinaryLocation(t testing.TB) string {
	return getSyftBinaryLocationByOS(t, runtime.GOOS, runtime.GOARCH)
}

func getSyftBinaryLocationByOS(t testing.TB, goOS, goArch string) string {
	// note: for amd64 we need to update the snapshot location with the v1 suffix
	// see : https://goreleaser.com/customization/build/#why-is-there-a-_v1-suffix-on-amd64-builds
	archPath := goArch
	if goArch == "amd64" {
		archPath = fmt.Sprintf("%s_v1", archPath)
	}

	bin := ""
	// note: there is a subtle - vs _ difference between these versions
	switch goOS {
	case "windows", "darwin", "linux":
		bin = path.Join(repoRoot(t), fmt.Sprintf("snapshot/%s-build_%s_%s/syft", goOS, goOS, archPath))
	default:
		t.Fatalf("unsupported OS: %s", goOS)
		return ""
	}

	envName := strings.ToUpper(fmt.Sprintf("SYFT_BINARY_LOCATION_%s_%s", goOS, goArch))
	if os.Getenv(envName) != bin {
		buildSyft(t, bin, goOS, goArch)
		// regardless if we have a successful build, don't attempt to keep building
		_ = os.Setenv(envName, bin)
	}

	return bin
}

func buildSyft(t testing.TB, outfile, goOS, goArch string) {
	dir := repoRoot(t)

	start := time.Now()

	stdout, stderr, err := buildSyftWithGo(dir, outfile, goOS, goArch)

	took := time.Now().Sub(start).Round(time.Millisecond)
	if err == nil {
		if len(stderr) == 0 {
			t.Logf("binary is up to date: %s in %v", outfile, took)
		} else {
			t.Logf("built binary: %s in %v\naffected paths:\n%s", outfile, took, stderr)
		}
	} else {
		t.Fatalf("unable to build binary: %s -- %v\nSTDOUT:\n%s\nSTDERR:\n%s", outfile, err, stdout, stderr)
	}
}

func buildSyftWithGo(dir, outfile, goOS, goArch string) (string, string, error) {
	d := yaml.NewDecoder(strings.NewReader(goreleaserYamlContents(dir)))
	type releaser struct {
		Builds []struct {
			ID      string `yaml:"id"`
			LDFlags string `yaml:"ldflags"`
		} `yaml:"builds"`
	}
	r := releaser{}
	_ = d.Decode(&r)
	ldflags := ""
	for _, b := range r.Builds {
		if b.ID == "linux-build" {
			ldflags = executeTemplate(b.LDFlags, struct {
				Version string
				Commit  string
				Date    string
				Summary string
			}{
				Version: "SNAPSHOT", // should contain "SNAPSHOT" so update checks are skipped
				Commit:  "COMMIT",
				Date:    "DATE",
				Summary: "SUMMARY",
			})
			break
		}
	}

	cmd := exec.Command("go",
		"build",
		"-v",
		"-o", outfile,
		"-trimpath",
		"-ldflags", ldflags,
		"./cmd/syft",
	)

	cmd.Dir = dir
	stdout, stderr, err := runCommand(cmd, map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        goOS,
		"GOARCH":      goArch,
	})
	return stdout, stderr, err
}

func goreleaserYamlContents(dir string) string {
	b, _ := os.ReadFile(path.Join(dir, ".goreleaser.yaml"))
	return string(b)
}

func executeTemplate(tpl string, data any) string {
	t, err := template.New("tpl").Parse(tpl)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	out := &bytes.Buffer{}
	err = t.Execute(out, data)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return out.String()
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
