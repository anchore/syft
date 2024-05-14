package main

import (
	"context"
	"crypto"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const defaultImage = "alpine:3.19"

func main() {
	// automagically get a source.Source for arbitrary string input
	src := getSource(imageReference())

	// will catalog the given source and return a SBOM keeping in mind several configurable options
	sbom := getSBOM(src)

	// show a simple package summary
	summarize(sbom)

	// show the alpine-configuration cataloger results
	showAlpineConfiguration(sbom)
}

func imageReference() string {
	// read an image string reference from the command line or use a default
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return defaultImage
}

func getSource(input string) source.Source {
	fmt.Println("detecting source type for input:", input, "...")

	src, err := syft.GetSource(context.Background(), input, nil)

	if err != nil {
		panic(err)
	}

	return src
}

func getSBOM(src source.Source) sbom.SBOM {
	fmt.Println("creating SBOM...")

	cfg := syft.DefaultCreateSBOMConfig().
		// run the catalogers in parallel (5 at a time concurrently max)
		WithParallelism(5).
		// bake a specific tool name and version into the SBOM
		WithTool("my-tool", "v1.0").
		// catalog all files with 3 digests
		WithFilesConfig(
			filecataloging.DefaultConfig().
				WithSelection(file.AllFilesSelection).
				WithHashers(
					crypto.MD5,
					crypto.SHA1,
					crypto.SHA256,
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

	fmt.Printf("All 'alpine-configuration' packages: %s\n", p.Version)
	meta, err := yaml.Marshal(p.Metadata)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(meta))

}
