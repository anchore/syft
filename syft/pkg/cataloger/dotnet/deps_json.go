package dotnet

import (
	"encoding/json"
	"fmt"

	"github.com/scylladb/go-set/strset"

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
	NameVersion                              string
	Targets                                  *depsTarget
	Library                                  *depsLibrary
	RuntimeAndResourcePathsByRelativeDLLPath map[string]string
	Executables                              []logicalDotnetPE
}

type logicalDepsJSON struct {
	Location              file.Location
	RuntimeTarget         runtimeTarget
	PackagesByNameVersion map[string]logicalDepsJSONPackage
	PackageNameVersions   *strset.Set
}

func (l logicalDepsJSON) RootPackage() (logicalDepsJSONPackage, bool) {
	rootName := getDepsJSONFilePrefix(l.Location.RealPath)
	if rootName == "" {
		return logicalDepsJSONPackage{}, false
	}

	// iterate over the map to find the root package. If we don't find the root package, that's ok! We still want to
	// get all of the packages that are defined in this deps.json file.
	for _, p := range l.PackagesByNameVersion {
		name, _ := extractNameAndVersion(p.NameVersion)
		// there can be multiple projects defined in a deps.json and only by convention is the root project the same name as the deps.json file
		// however there are other configurations that can lead to differences (e.g. "tool_fsc" vs "fsc.deps.json").
		if p.Library != nil && p.Library.Type == "project" && name == rootName {
			return p, true
		}
	}
	return logicalDepsJSONPackage{}, false
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
	nameVersions := strset.New()

	for _, targets := range deps.Targets {
		for libName, target := range targets {
			_, exists := packageMap[libName]
			if !exists {
				var lib *depsLibrary
				l, ok := deps.Libraries[libName]
				if ok {
					lib = &l
				}
				paths := make(map[string]string)
				for path := range target.Runtime {
					paths[trimLibPrefix(path)] = path
				}
				for path := range target.Resources {
					trimmedPath := trimLibPrefix(path)
					if _, exists := paths[trimmedPath]; exists {
						continue
					}
					paths[trimmedPath] = path
				}

				p := &logicalDepsJSONPackage{
					NameVersion:                              libName,
					Library:                                  lib,
					Targets:                                  &target,
					RuntimeAndResourcePathsByRelativeDLLPath: paths,
				}
				packageMap[libName] = p
				nameVersions.Add(libName)
			}
		}
	}
	packages := make(map[string]logicalDepsJSONPackage)
	for _, p := range packageMap {
		packages[p.NameVersion] = *p
	}

	return logicalDepsJSON{
		Location:              deps.Location,
		RuntimeTarget:         deps.RuntimeTarget,
		PackagesByNameVersion: packages,
		PackageNameVersions:   nameVersions,
	}
}
