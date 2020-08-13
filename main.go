/*
Syft is a CLI tool and go library for generating a Software Bill of Materials (SBOM) from container images and filesystems.

Note that Syft is both a command line tool as well as a library. See the syft/ child package for library functionality.
*/
package main

import (
	"github.com/anchore/syft/cmd"
)

func main() {
	cmd.Execute()
}
