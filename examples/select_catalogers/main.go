package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const defaultImage = "alpine:3.19"

func main() {
	// automagically get a source.Source for arbitrary string input
	src := getSource(imageReference())

	// catalog the given source and return a SBOM
	// let's explicitly use catalogers that are:
	// - for installed software
	// - used in the directory scan
	sbom := getSBOM(src, pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag)

	// Show a basic catalogers and input configuration used
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sbom.Descriptor.Configuration); err != nil {
		panic(err)
	}

}

func imageReference() string {
	// read an image string reference from the command line or use a default
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return defaultImage
}

func getSource(input string) source.Source {
	src, err := syft.GetSource(context.Background(), input, nil)

	if err != nil {
		panic(err)
	}

	return src
}

func getSBOM(src source.Source, defaultTags ...string) sbom.SBOM {
	cfg := syft.DefaultCreateSBOMConfig().
		WithCatalogerSelection(
			// here you can sub-select, add, remove catalogers from the default selection...
			// or replace the default selection entirely!
			pkgcataloging.NewSelectionRequest().
				WithDefaults(defaultTags...),
		)

	s, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		panic(err)
	}

	return *s
}
