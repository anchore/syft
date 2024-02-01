package main

import (
	"encoding/json"
	"os"

	"github.com/anchore/syft/syft/source"
)

/*
 This example demonstrates how to create a source object from a generic string input.

 Example inputs:
    alpine:3.19                              pull an image from the docker daemon, podman, or the registry (based on what's available)
    ./my.tar                                 interpret a local archive as an OCI archive, docker save archive, or raw file from disk to catalog
    docker:yourrepo/yourimage:tag            explicitly use the Docker daemon
    podman:yourrepo/yourimage:tag            explicitly use the Podman daemon
    registry:yourrepo/yourimage:tag          pull image directly from a registry (no container runtime required)
    docker-archive:path/to/yourimage.tar     use a tarball from disk for archives created from "docker save"
    oci-archive:path/to/yourimage.tar        use a tarball from disk for OCI archives (from Skopeo or otherwise)
    oci-dir:path/to/yourimage                read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    singularity:path/to/yourimage.sif        read directly from a Singularity Image Format (SIF) container on disk
    dir:path/to/yourproject                  read directly from a path on disk (any directory)
    file:path/to/yourproject/file            read directly from a path on disk (any single file)

*/

const defaultImage = "alpine:3.19"

func main() {
	detection, err := source.Detect(
		imageReference(),
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
