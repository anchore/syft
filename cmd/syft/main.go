package main

import (
	"log"

	_ "modernc.org/sqlite"

	"github.com/anchore/syft/cmd/syft/cli"
)

func main() {
	c := cli.New()

	if err := c.Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
