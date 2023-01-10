package main

import (
	"log"
	"os"
	"runtime"
	"runtime/pprof"

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
	f, err := os.Create("mem.pprof")
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer f.Close() // error handling omitted for example
	runtime.GC()    // get up-to-date statistics
	if err := pprof.WriteHeapProfile(f); err != nil {
		log.Fatal("could not write memory profile: ", err)
	}
}
