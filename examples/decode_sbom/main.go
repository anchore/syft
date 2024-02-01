package main

import (
	"fmt"
	"github.com/anchore/syft/syft/format"
	"os"
)

const exampleFile = "alpine.syft.json"

func main() {
	// read file from sys args (or use the default)
	var filePath string
	if len(os.Args) < 2 {
		filePath = exampleFile
	} else {
		filePath = os.Args[1]
	}

	file, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}

	// decode the SBOM
	sbom, sbomFormat, formatVersion, err := format.Decode(file)
	if err != nil {
		panic(err)
	}

	fmt.Printf("SBOM format: %s@%s\n", sbomFormat, formatVersion)

	// print packages found...
	fmt.Println("\nPackages found:")
	for _, pkg := range sbom.Artifacts.Packages.Sorted() {
		fmt.Printf("   %s : %s@%s (%s)\n", pkg.ID(), pkg.Name, pkg.Version, pkg.Type)
	}

	// print files found...
	fmt.Println("\nFiles found:")
	for c, f := range sbom.Artifacts.FileMetadata {
		fmt.Printf("   %s : %s\n", c.ID(), f.Path)
	}
}
