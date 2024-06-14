package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"

	"golang.org/x/mod/modfile"

	_ "github.com/anchore/binny/cmd/binny/cli" // so go mod tidy doesn't remove necessary packages
)

func main() {
	noerr(buildIfMissing(exe("../.tool/binny"), "github.com/anchore/binny/cmd/binny"))
	noerr(os.Chdir(".."))
	noerr(run(exe(".tool/binny"), "install", "-v"))
	noerr(run(exe(".tool/task"), os.Args[1:]...))
}

func buildIfMissing(file, pkg string) error {
	_, err := os.Stat(file)
	if err == nil {
		return nil
	}
	write("Building: %s", pkg)
	return run("go", "build", "-o", file, "-ldflags", "-w -s -extldflags '-static' -X main.version="+binnyVersion(), pkg)
}

//nolint:gosec
func run(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}

func noerr(e error) {
	if e != nil {
		write("ERROR: %v", e)
		os.Exit(1)
	}
}

func noerrGet[T any](t T, e error) T {
	if e != nil {
		write("ERROR: %v", e)
		os.Exit(1)
	}
	return t
}

func write(msg string, args ...any) {
	_, _ = fmt.Fprintln(os.Stderr, fmt.Sprintf(msg, args...))
}

func exe(s string) string {
	out := filepath.Join(path.Split(s))
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	return out
}

func binnyVersion() string {
	contents := noerrGet(os.ReadFile("go.mod"))
	f := noerrGet(modfile.Parse("go.mod", contents, nil))
	for _, r := range f.Require {
		if r.Mod.Path == "github.com/anchore/binny" {
			return r.Mod.Version
		}
	}
	return "UNKNOWN"
}
