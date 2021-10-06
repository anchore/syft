//build:ignore
package main

import (
	"os"

	"golang.org/x/term"
)

func main() {
	t := term.NewTerminal(os.Stdout, "foo")
	t.Write([]byte("hello anchore"))
}
