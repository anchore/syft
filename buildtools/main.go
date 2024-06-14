package main

import (
	"fmt"
	"os"
	"os/exec"

	_ "github.com/anchore/binny/cmd/binny/cli" // so go mod tidy doesn't remove necessary packages
)

func main() {
	noerr(buildIfMissing("../.tool/binny", "github.com/anchore/binny/cmd/binny"))
	noerr(os.Chdir(".."))
	noerr(run(".tool/binny", "install", "-v"))
	noerr(run(".tool/task", os.Args[1:]...))
}

func buildIfMissing(file, pkg string) error {
	_, err := os.Stat(file)
	if err == nil {
		return nil
	}
	write("Building: %s", pkg)
	return run("go", "build", "-o", file, pkg)
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

func write(msg string, args ...any) {
	_, _ = fmt.Fprintln(os.Stderr, fmt.Sprintf(msg, args...))
}
