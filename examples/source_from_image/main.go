package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image/oci"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

/*
 This shows how to create a source from an image reference. This is useful when you are programmatically always
 expecting to catalog a container image and always from the same source (e.g. docker daemon, podman, registry, etc).
*/

const defaultImage = "alpine:3.19"

func main() {
	// using oci.Registry causes the lookup to always use the registry, there are several other "Source" options here
	img, err := stereoscope.GetImageFromSource(context.Background(), imageReference(), oci.Registry, stereoscope.WithPlatform("linux/amd64"))
	if err != nil {
		panic(err)
	}

	src := stereoscopesource.New(img, stereoscopesource.ImageConfig{
		Reference: imageReference(),
	})

	// Show a basic description of the source to the screen
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(src.Describe()); err != nil {
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
