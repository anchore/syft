package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
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
	userInput := imageReference()

	// parse the scheme against the known set of schemes
	schemeSource, newUserInput := stereoscope.ExtractSchemeSource(userInput, allSourceTags()...)

	// set up the GetSourceConfig
	getSourceCfg := syft.DefaultGetSourceConfig()
	if schemeSource != "" {
		getSourceCfg = getSourceCfg.WithSources(schemeSource)
		userInput = newUserInput
	}
	src, err := syft.GetSource(context.Background(), userInput, getSourceCfg)

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

func allSourceTags() []string {
	return collections.TaggedValueSet[source.Provider]{}.Join(sourceproviders.All("", nil)...).Tags()
}
