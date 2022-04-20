package main

import (
	"log"

	"github.com/anchore/syft/cmd/syft/cli"
)

func main() {
	cli, err := cli.New()
	if err != nil {
		log.Fatalf("error during command construction: %v", err)
	}

	if err := cli.Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
