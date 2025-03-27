package dotnet

import (
	"encoding/json"
	"fmt"
	"strings"

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
	NameVersion string
	Targets     *depsTarget
	Library     *depsLibrary

	// RuntimePathsByRelativeDLLPath is a map of the relative path to the DLL relative to the deps.json file
	// to the target path as described in the deps.json target entry under "runtime".
	RuntimePathsByRelativeDLLPath map[string]string

	// ResourcePathsByRelativeDLLPath is a map of the relative path to the DLL relative to the deps.json file
	// to the target path as described in the deps.json target entry under "resource".
	ResourcePathsByRelativeDLLPath map[string]string

	// Executables is a list of all the executables that are part of this package. This is populated by the PE cataloger
	// and not something that is found in the deps.json file. This allows us to associate the PE files with this package
	// based on the relative path to the DLL.
	Executables []logicalPE
}

type logicalDepsJSON struct {
	Location              file.Location
	RuntimeTarget         runtimeTarget
	PackagesByNameVersion map[string]logicalDepsJSONPackage
	PackageNameVersions   *strset.Set
	BundlingDetected      bool
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

var knownBundlers = strset.New(
	"ILRepack.Lib.MSBuild.Task", // The most official use of ILRepack https://github.com/gluck/il-repack
	"ILRepack.Lib",              // library interface for ILRepack
	"ILRepack.Lib.MSBuild",      // uses Cecil 0.10
	"ILRepack.Lib.NET",          // uses ModuleDefinitions instead of filenames
	"ILRepack.NETStandard",      // .NET Standard compatible version
	"ILRepack.FullAuto",         // https://github.com/kekyo/ILRepack.FullAuto
	"ILMerge",                   // deprecated, but still used in some projects https://github.com/dotnet/ILMerge
	"JetBrains.Build.ILRepack",  // generally from https://www.nuget.org/packages?q=ilrepack&sortBy=relevance

	// other bundling/modification tools found in results
	"PostSharp.Community.Packer", // Embeds dependencies as resources
	"Brokenevent.ILStrip",        // assembly cleaner (removes unused parts)
	"Brokenevent.ILStrip.CLI",    // command-line/MSBuild variant
	"Costura.Fody",               // referenced in MSBuildRazorCompiler.Lib
	"Fody",                       // IL weaving framework
)

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
				runtimePaths := make(map[string]string)
				for path := range target.Runtime {
					runtimePaths[trimLibPrefix(path)] = path
				}
				resourcePaths := make(map[string]string)
				for path := range target.Resources {
					trimmedPath := trimLibPrefix(path)
					if _, exists := resourcePaths[trimmedPath]; exists {
						continue
					}
					resourcePaths[trimmedPath] = path
				}

				p := &logicalDepsJSONPackage{
					NameVersion:                    libName,
					Library:                        lib,
					Targets:                        &target,
					RuntimePathsByRelativeDLLPath:  runtimePaths,
					ResourcePathsByRelativeDLLPath: resourcePaths,
				}
				packageMap[libName] = p
				nameVersions.Add(libName)
			}
		}
	}
	packages := make(map[string]logicalDepsJSONPackage)
	var bundlingDetected bool
	for _, p := range packageMap {
		name := strings.Split(p.NameVersion, "/")[0]
		if !bundlingDetected && knownBundlers.Has(name) {
			bundlingDetected = true
		}
		packages[p.NameVersion] = *p
	}

	return logicalDepsJSON{
		Location:              deps.Location,
		RuntimeTarget:         deps.RuntimeTarget,
		PackagesByNameVersion: packages,
		PackageNameVersions:   nameVersions,
		BundlingDetected:      bundlingDetected,
	}
}
