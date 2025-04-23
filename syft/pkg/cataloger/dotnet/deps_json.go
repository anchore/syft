package dotnet

import (
	"encoding/json"
	"fmt"
	"regexp"
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
	Compile      map[string]map[string]string `json:"compile"`
	Native       map[string]map[string]string `json:"native"`
}

func (t depsTarget) nativePaths() *strset.Set {
	results := strset.New()
	for path := range t.Native {
		results.Add(path)
	}
	return results
}

func (t depsTarget) compilePaths() map[string]string {
	result := make(map[string]string)
	for path := range t.Compile {
		trimmedPath := trimLibPrefix(path)
		if _, exists := result[trimmedPath]; exists {
			continue
		}
		result[trimmedPath] = path
	}
	return result
}

func (t depsTarget) resourcePaths() map[string]string {
	result := make(map[string]string)
	for path := range t.Resources {
		trimmedPath := trimLibPrefix(path)
		if _, exists := result[trimmedPath]; exists {
			continue
		}
		result[trimmedPath] = path
	}
	return result
}

func (t depsTarget) runtimePaths() map[string]string {
	result := make(map[string]string)
	for path := range t.Runtime {
		result[trimLibPrefix(path)] = path
	}
	return result
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

	// anyChildClaimsDLLs is a flag that indicates if any of the children of this package claim a DLL associated with them in the deps.json.
	anyChildClaimsDLLs bool

	// anyChildHasDLLs is a flag that indicates if any of the children of this package have a DLL associated with them (found on disk).
	anyChildHasDLLs bool

	// RuntimePathsByRelativeDLLPath is a map of the relative path to the DLL relative to the deps.json file
	// to the target path as described in the deps.json target entry under "runtime".
	RuntimePathsByRelativeDLLPath map[string]string

	// ResourcePathsByRelativeDLLPath is a map of the relative path to the DLL relative to the deps.json file
	// to the target path as described in the deps.json target entry under "resource".
	ResourcePathsByRelativeDLLPath map[string]string

	// CompilePathsByRelativeDLLPath is a map of the relative path to the DLL relative to the deps.json file
	// to the target path as described in the deps.json target entry under "compile".
	CompilePathsByRelativeDLLPath map[string]string

	// NativePathsByRelativeDLLPath is a map of the relative path to the DLL relative to the deps.json file
	// to the target path as described in the deps.json target entry under "native". These should not have
	// any runtime references to trim from the front of the path.
	NativePaths *strset.Set

	// Executables is a list of all the executables that are part of this package. This is populated by the PE cataloger
	// and not something that is found in the deps.json file. This allows us to associate the PE files with this package
	// based on the relative path to the DLL.
	Executables []logicalPE
}

func (l *logicalDepsJSONPackage) dependencyNameVersions() []string {
	if l.Targets == nil {
		return nil
	}
	var results []string
	for name, version := range l.Targets.Dependencies {
		results = append(results, createNameAndVersion(name, version))
	}
	return results
}

// ClaimsDLLs indicates if this package has any DLLs associated with it (directly or indirectly with a dependency).
func (l *logicalDepsJSONPackage) ClaimsDLLs() bool {
	selfClaim := len(l.RuntimePathsByRelativeDLLPath) > 0 || len(l.ResourcePathsByRelativeDLLPath) > 0 || len(l.CompilePathsByRelativeDLLPath) > 0 || len(l.NativePaths.List()) > 0
	return selfClaim || l.anyChildClaimsDLLs
}

func (l *logicalDepsJSONPackage) FoundDLLs() bool {
	return len(l.Executables) > 0 || l.anyChildHasDLLs
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
			if exists {
				continue
			}

			var lib *depsLibrary
			l, ok := deps.Libraries[libName]
			if ok {
				lib = &l
			}

			p := &logicalDepsJSONPackage{
				NameVersion:                    libName,
				Library:                        lib,
				Targets:                        &target,
				RuntimePathsByRelativeDLLPath:  target.runtimePaths(),
				ResourcePathsByRelativeDLLPath: target.resourcePaths(),
				CompilePathsByRelativeDLLPath:  target.compilePaths(),
				NativePaths:                    target.nativePaths(),
			}
			packageMap[libName] = p
			nameVersions.Add(libName)
		}
	}
	packages := make(map[string]logicalDepsJSONPackage)
	var bundlingDetected bool
	for _, p := range packageMap {
		name := strings.Split(p.NameVersion, "/")[0]
		if !bundlingDetected && knownBundlers.Has(name) {
			bundlingDetected = true
		}
		p.anyChildClaimsDLLs = searchForDLLClaims(packageMap, p.dependencyNameVersions()...)
		p.anyChildHasDLLs = searchForDLLEvidence(packageMap, p.dependencyNameVersions()...)
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

type visitorFunc func(p *logicalDepsJSONPackage) bool

// searchForDLLEvidence recursively searches for executables found for any of the given nameVersions and children recursively.
func searchForDLLEvidence(packageMap map[string]*logicalDepsJSONPackage, nameVersions ...string) bool {
	return traverseDependencies(packageMap, func(p *logicalDepsJSONPackage) bool {
		return p.FoundDLLs()
	}, nameVersions...)
}

// searchForDLLClaims recursively searches for DLL claims in the deps.json for any of the given nameVersions and children recursively.
func searchForDLLClaims(packageMap map[string]*logicalDepsJSONPackage, nameVersions ...string) bool {
	return traverseDependencies(packageMap, func(p *logicalDepsJSONPackage) bool {
		return p.ClaimsDLLs()
	}, nameVersions...)
}

func traverseDependencies(packageMap map[string]*logicalDepsJSONPackage, visitor visitorFunc, nameVersions ...string) bool {
	if len(nameVersions) == 0 {
		return false
	}

	for _, nameVersion := range nameVersions {
		if p, ok := packageMap[nameVersion]; ok {
			if visitor(p) {
				return true
			}

			var children []string
			for name, version := range p.Targets.Dependencies {
				children = append(children, createNameAndVersion(name, version))
			}

			if traverseDependencies(packageMap, visitor, children...) {
				return true
			}
		}
	}

	return false
}

var libPathPattern = regexp.MustCompile(`^(?:runtimes/[^/]+/)?lib/net[^/]+/(?P<targetPath>.+)`)

// trimLibPrefix removes prefixes like "lib/net6.0/" or "runtimes/linux-arm/lib/netcoreapp2.2/" from a path.
// It captures and returns everything after the framework version section using a named capture group.
func trimLibPrefix(s string) string {
	if match := libPathPattern.FindStringSubmatch(s); len(match) > 1 {
		// Get the index of the named capture group
		targetPathIndex := libPathPattern.SubexpIndex("targetPath")
		if targetPathIndex != -1 {
			return match[targetPathIndex]
		}
	}
	return s
}
