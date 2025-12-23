package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/text/language"
)

func main() {
	// use stdlib packages
	fmt.Println("Hello from Go!")
	fmt.Println(strings.ToUpper("test"))

	// use golang.org/x package
	tag := language.English
	fmt.Println(tag.String())

	// use third-party package
	spew.Dump(os.Args)

	// use encoding/json
	data, _ := json.Marshal(map[string]string{"hello": "world"})
	fmt.Println(string(data))
}
