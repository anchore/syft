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

const imageRef = "alpine:3.19"

func main() {
	// automagically get a source.Source for arbitrary string input
	src := getSource(imageRef)

	// catalog the given source and return a SBOM
	sbom := getSBOM(src)

	// take the SBOM object and encode it into the syft-json representation
	bytes := formatSBOM(sbom)

	// show the SBOM!
	fmt.Println(string(bytes))
}

func getSource(input string) source.Source {
	detection, err := source.Detect(input,
		source.DetectConfig{
			DefaultImageSource: "docker",
		},
	)

	if err != nil {
		panic(err)
	}

	src, err := detection.NewSource(source.DefaultDetectionSourceConfig())

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
