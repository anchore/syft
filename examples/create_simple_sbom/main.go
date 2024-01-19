package main

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

/*
This example demonstrates the most straight forward way to create an SBOM.
  - getSource() will automagically get a source.Source for arbitrary string input
  - getSBOM() will catalog the given source and return a SBOM
  - formatSBOM() will take the SBOM object and encode it into the syft-json representation
*/

func main() {
	src := getSource("alpine:3.19")

	sbom := getSBOM(src)

	bytes := formatSBOM(sbom)

	fmt.Println(string(bytes))
}

func getSource(input string) source.Source {
	// refactor: source.Detect should take pointer? (to allow for nil default)
	// refactor: keith has suggestions for refactoring the source.Detection flow
	detection, err := source.Detect(input, source.DetectConfig{
		// refactor: this is a magic string
		DefaultImageSource: "docker",
	})

	if err != nil {
		panic(err)
	}

	// refactor: take pointer and allow for nil?
	src, err := detection.NewSource(source.DetectionSourceConfig{})

	if err != nil {
		panic(err)
	}

	return src
}

func getSBOM(src source.Source) sbom.SBOM {
	s, err := syft.CreateSBOM(context.Background(), src, nil)
	if err != nil {
		panic(err)
	}

	return *s
}

func formatSBOM(s sbom.SBOM) []byte {
	bytes, err := format.Encode(s, syftjson.NewFormatEncoder())
	if err != nil {
		panic(err)
	}
	return bytes
}
