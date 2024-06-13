package main

import (
	"fmt"
	"os"
	"os/exec"

	_ "github.com/go-task/task/v3"
)

func main() {
	err := runTask(os.Args[1:]...)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, fmt.Sprintf("ERROR: %v", err))
	}
}

//nolint:gosec
func runTask(args ...string) error {
	taskArgs := []string{"run", "github.com/go-task/task/v3/cmd/task"}
	c := exec.Command("go", append(taskArgs, args...)...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}
