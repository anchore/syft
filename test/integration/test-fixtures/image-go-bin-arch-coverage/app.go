//build:ignore
package main

import (
	"fmt"
	"os"

	"golang.org/x/net/html"
	"golang.org/x/term"
)

var test = html.ErrBufferExceeded

func main() {
	t := term.NewTerminal(os.Stdout, "foo")
	t.Write([]byte("hello anchore"))
	t.Write([]byte(fmt.Sprintf("%v", test)))
}
