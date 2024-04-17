package main

import (
	"context"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/syftjson"
)

// This example demonstrates how to create an SBOM, pulling only from "registry", with error handling omitted
func main() {
	image := "alpine:3.19"

	src, _ := syft.GetSource(context.Background(), image, syft.DefaultGetSourceConfig().WithSources("registry"))

	sbom, _ := syft.CreateSBOM(context.Background(), src, syft.DefaultCreateSBOMConfig())

	_ = syftjson.NewFormatEncoder().Encode(os.Stdout, *sbom)
}
