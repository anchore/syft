package main

import (
	"log"

	"github.com/anchore/syft/cmd/syft/cli"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
