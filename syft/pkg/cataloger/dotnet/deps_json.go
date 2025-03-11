package dotnet

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/file"
)

type depsJSON struct {
	Location      file.Location
	RuntimeTarget runtimeTarget                    `json:"runtimeTarget"`
	Targets       map[string]map[string]depsTarget `json:"targets"`
	Libraries     map[string]depsLibrary           `json:"libraries"`
}

type runtimeTarget struct {
	Name string `json:"name"`
}

type depsTarget struct {
	Dependencies map[string]string            `json:"dependencies"`
	Runtime      map[string]map[string]string `json:"runtime"`
	Resources    map[string]map[string]string `json:"resources"`
}

type depsLibrary struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	Sha512   string `json:"sha512"`
	HashPath string `json:"hashPath"`
}

// logicalDepsJSONPackage merges target and library information for a given package from all dep.json entries.
// Note: this is not a real construct of the deps.json, just a useful reorganization of the data for downstream processing.
type logicalDepsJSONPackage struct {
	NameVersion string
	Targets     *depsTarget
	Library     *depsLibrary
	Executables []logicalDotnetPE
}

type logicalDepsJSON struct {
	Location      file.Location
	RuntimeTarget runtimeTarget
	Packages      map[string]logicalDepsJSONPackage
}

func newDepsJSON(reader file.LocationReadCloser) (*depsJSON, error) {
	var doc depsJSON
	dec := json.NewDecoder(reader)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to parse deps.json file: %w", err)
	}
	doc.Location = reader.Location
	return &doc, nil
}

func getLogicalDepsJSON(deps depsJSON) logicalDepsJSON {
	packageMap := make(map[string]*logicalDepsJSONPackage)

	for _, targets := range deps.Targets {
		for libName, target := range targets {
			_, exists := packageMap[libName]
			if !exists {
				var lib *depsLibrary
				l, ok := deps.Libraries[libName]
				if ok {
					lib = &l
				}
				p := &logicalDepsJSONPackage{
					NameVersion: libName,
					Library:     lib,
					Targets:     &target,
				}
				packageMap[libName] = p
			}
		}
	}
	packages := make(map[string]logicalDepsJSONPackage)
	for _, p := range packageMap {
		packages[p.NameVersion] = *p
	}

	return logicalDepsJSON{
		Location:      deps.Location,
		RuntimeTarget: deps.RuntimeTarget,
		Packages:      packages,
	}
}
