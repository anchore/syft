package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/syft/format"
)

//go:embed alpine.syft.json
var sbomContents string

func main() {
	// decode the SBOM
	fmt.Println("decoding SBOM...")
	sbom, sbomFormat, formatVersion, err := format.Decode(sbomReader())
	if err != nil {
		fmt.Printf("failed to decode sbom: %+v\n", err)
		os.Exit(1)
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

func sbomReader() io.Reader {
	// read file from sys args (or use the default)
	var reader io.Reader
	if len(os.Args) < 2 {
		reader = strings.NewReader(sbomContents)
	} else {
		var err error
		reader, err = os.Open(os.Args[1])
		if err != nil {
			panic(err)
		}
	}
	return reader
}
