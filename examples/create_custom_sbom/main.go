package main

import (
	"context"
	"crypto"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func main() {
	// automagically get a source.Source for arbitrary string input
	src := getSource("alpine:3.19")

	// will catalog the given source and return a SBOM keeping in mind several configurable options
	sbom := getSBOM(src)

	// show a simple package summary
	summarize(sbom)

	// show the alpine-configuration cataloger results
	showAlpineConfiguration(sbom)
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
	cfg := syft.DefaultCreateSBOMConfig().
		// run the catalogers in parallel (5 at a time concurrently max)
		WithParallelism(5).
		// bake a specific tool name and version into the SBOM
		WithTool("my-tool", "v1.0").
		// catalog all files with 3 digests
		WithFilesConfig(
			// refactor: need to add WithContent() and related
			filecataloging.DefaultConfig().
				WithSelection(file.AllFilesSelection).
				WithHashers(
					[]crypto.Hash{
						crypto.MD5,
						crypto.SHA1,
						crypto.SHA256,
					},
				),
		).
		// only use OS related catalogers that would have been used with the kind of
		// source type (container image or directory), but also add a specific python cataloger
		WithCatalogerSelection(
			pkgcataloging.NewSelectionRequest().
				WithSubSelections("os").
				WithAdditions("python-package-cataloger"),
		).
		// which relationships to include
		WithRelationshipsConfig(
			cataloging.RelationshipsConfig{
				PackageFileOwnership:                          true,
				PackageFileOwnershipOverlap:                   true,
				ExcludeBinaryPackagesWithFileOwnershipOverlap: true,
			},
		).
		// add your own cataloger to the mix
		WithCatalogers(
			pkgcataloging.NewAlwaysEnabledCatalogerReference(
				newAlpineConfigurationCataloger(),
			),
		)

	s, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		panic(err)
	}

	return *s
}

func summarize(s sbom.SBOM) {
	fmt.Printf("Cataloged %d packages:\n", s.Artifacts.Packages.PackageCount())
	for _, p := range s.Artifacts.Packages.Sorted() {
		fmt.Printf(" - %s@%s (%s)\n", p.Name, p.Version, p.Type)
	}
	fmt.Println()
}

func showAlpineConfiguration(s sbom.SBOM) {
	pkgs := s.Artifacts.Packages.PackagesByName("alpine-configuration")
	if len(pkgs) == 0 {
		fmt.Println("no alpine-configuration package found")
		return
	}

	p := pkgs[0]

	fmt.Printf("alpine-configuration: %s\n", p.Version)
	meta, err := yaml.Marshal(p.Metadata)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(meta))

}
