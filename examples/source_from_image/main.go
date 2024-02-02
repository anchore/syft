package main

import (
	"encoding/json"
	"os"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

/*
 This shows how to create a source from an image reference. This is useful when you are programmatically always
 expecting to catalog a container image and always from the same source (e.g. docker daemon, podman, registry, etc).
*/

const defaultImage = "alpine:3.19"

func main() {
	platform, err := image.NewPlatform("linux/amd64")
	if err != nil {
		panic(err)
	}

	src, err := source.NewFromStereoscopeImage(
		source.StereoscopeImageConfig{
			Reference: imageReference(),
			From:      image.OciRegistrySource, // always use the registry, there are several other "Source" options here
			Platform:  platform,
		},
	)

	if err != nil {
		panic(err)
	}

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
