package python

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

type PipfileLock struct {
	Meta struct {
		Hash struct {
			Sha256 string `json:"sha256"`
		} `json:"hash"`
		PipfileSpec int `json:"pipfile-spec"`
		Requires    struct {
			PythonVersion string `json:"python_version"`
		} `json:"requires"`
		Sources []struct {
			Name      string `json:"name"`
			URL       string `json:"url"`
			VerifySsl bool   `json:"verify_ssl"`
		} `json:"sources"`
	} `json:"_meta"`
	Default map[string]Dependency `json:"default"`
	Develop map[string]Dependency `json:"develop"`
}

type Dependency struct {
	Version string `json:"version"`
}

// integrity check
var _ common.ParserFn = parsePipfileLock

// parsePipfileLock is a parser function for Pipfile.lock contents, returning "Default" python packages discovered.
func parsePipfileLock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	packages := make([]*pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var lock PipfileLock
		if err := dec.Decode(&lock); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse Pipfile.lock file: %w", err)
		}
		for name, pkgMeta := range lock.Default {
			version := strings.TrimPrefix(pkgMeta.Version, "==")
			packages = append(packages, &pkg.Package{
				Name:     name,
				Version:  version,
				Language: pkg.Python,
				Type:     pkg.PythonPkg,
			})
		}
	}

	return packages, nil, nil
}
