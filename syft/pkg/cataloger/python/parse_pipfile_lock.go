package python

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type pipfileLock struct {
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
	Default map[string]pipfileLockDependency `json:"default"`
	Develop map[string]pipfileLockDependency `json:"develop"`
}

type pipfileLockDependency struct {
	Hashes  []string `json:"hashes"`
	Version string   `json:"version"`
	Index   string   `json:"index"`
}

type pipfileLockParser struct {
	cfg             CatalogerConfig
	licenseResolver pythonLicenseResolver
}

func newPipfileLockParser(cfg CatalogerConfig) pipfileLockParser {
	return pipfileLockParser{
		cfg:             cfg,
		licenseResolver: newPythonLicenseResolver(cfg),
	}
}

// parsePipfileLock is a parser function for Pipfile.lock contents, returning "Default" python packages discovered.
func (plp pipfileLockParser) parsePipfileLock(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs := make([]pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var lock pipfileLock
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse Pipfile.lock file: %w", err)
		}
		sourcesMap := map[string]string{}
		for _, source := range lock.Meta.Sources {
			sourcesMap[source.Name] = source.URL
		}
		for name, pkgMeta := range lock.Default {
			var index string
			if pkgMeta.Index != "" {
				index = sourcesMap[pkgMeta.Index]
			} else {
				// https://pipenv.pypa.io/en/latest/indexes.html
				index = "https://pypi.org/simple"
			}
			version := strings.TrimPrefix(pkgMeta.Version, "==")
			pkgs = append(pkgs, newPackageForIndexWithMetadata(ctx, plp.licenseResolver, name, version, pkg.PythonPipfileLockEntry{Index: index, Hashes: pkgMeta.Hashes}, reader.Location))
		}
	}

	pkg.Sort(pkgs)

	return pkgs, nil, nil
}
