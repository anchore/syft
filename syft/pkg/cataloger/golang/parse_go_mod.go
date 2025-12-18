package golang

import (
	"bufio"
	"context"
	"fmt"
	"go/build"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/afero"
	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type goModCataloger struct {
	usePackagesLib  bool
	licenseResolver goLicenseResolver
}

func newGoModCataloger(opts CatalogerConfig) *goModCataloger {
	return &goModCataloger{
		usePackagesLib:  opts.UsePackagesLib,
		licenseResolver: newGoLicenseResolver(modFileCatalogerName, opts),
	}
}

// parseGoModFile takes a go.mod and tries to resolve and lists all packages discovered.
func (c *goModCataloger) parseGoModFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) (pkgs []pkg.Package, relationships []artifact.Relationship, err error) {
	modDir := filepath.Dir(string(reader.Location.Reference().RealPath))
	digests, err := parseGoSumFile(resolver, reader)
	if err != nil {
		log.Debugf("unable to get go.sum: %v", err)
	}

	scanRoot := ""
	if dir, ok := resolver.(*fileresolver.Directory); ok && dir != nil {
		scanRoot = dir.Chroot.Base()
	}

	// base case go.mod file parsing
	modFile, err := c.parseModFileContents(reader)
	if err != nil {
		return nil, nil, err
	}

	// source analysis using go toolchain if available
	var sourceModules map[string]*packages.Module
	var catalogedModules []pkg.Package

	if c.usePackagesLib {
		var sourcePackages map[string][]pkgInfo
		var sourceDependencies map[string][]string
		var sourceModuleToPkg map[string]artifact.Identifiable

		sourcePackages, sourceModules, sourceDependencies, err = c.loadPackages(modDir, reader.Location)
		catalogedModules, sourceModuleToPkg = c.catalogModules(ctx, scanRoot, sourcePackages, sourceModules, reader, digests)
		relationships = buildModuleRelationships(catalogedModules, sourceDependencies, sourceModuleToPkg)
	}

	// only use go.mod packages NOT found in source analysis
	goModPackages := c.createGoModPackages(ctx, resolver, modFile, sourceModules, reader, digests)
	c.applyReplaceDirectives(ctx, resolver, modFile, goModPackages, reader, digests)
	c.applyExcludeDirectives(modFile, goModPackages)

	pkgs = c.assembleResults(catalogedModules, goModPackages)

	return pkgs, relationships, err
}

// loadPackages uses golang.org/x/tools/go/packages to get dependency information.
func (c *goModCataloger) loadPackages(modDir string, loc file.Location) (pkgs map[string][]pkgInfo, modules map[string]*packages.Module, dependencies map[string][]string, unknownErr error) {
	cfg := &packages.Config{
		// Mode flags control what information is loaded for each package.
		// Performance impact increases significantly with each additional flag:
		//
		// packages.NeedModule - Required for module metadata (path, version, replace directives).
		//   Essential for SBOM generation. Minimal performance impact.
		//
		// packages.NeedName - Required for package names & package Path. Minimal performance impact.
		//   Needed to identify packages and filter out standard library packages.
		//
		// packages.NeedFiles - Loads source file paths for each package.
		//   Moderate performance impact as it requires filesystem traversal.
		//   Required for license discovery.
		//
		// packages.NeedDeps - Loads the dependency graph between packages.
		//   High performance impact as it builds the complete import graph.
		//   Critical for generating accurate dependency relationships in SBOM.
		//
		// packages.NeedImports - Loads import information for each package.
		//   High performance impact, especially with large codebases.
		//   Required for building module-to-module dependency mappings.
		//
		// Adding flags like NeedTypes, NeedSyntax, or NeedTypesInfo would dramatically
		// increase memory usage and processing time (10x+ slower) but are not needed
		// for SBOM generation as we only require dependency and module metadata.
		Mode:  packages.NeedModule | packages.NeedName | packages.NeedFiles | packages.NeedDeps | packages.NeedImports,
		Dir:   modDir,
		Tests: true,
	}

	// From Go documentation: "all" expands to all packages in the main module
	// and their dependencies, including dependencies needed by tests.
	//
	// The special pattern "all" specifies all the active modules,
	// first the main module and then dependencies sorted by module path.
	// A pattern containing "..." specifies the active modules whose module paths match the pattern.
	// On implementation we could not find a test case that differentiated between all and ...
	// There may be a case where ... is non inclusive so we default to all for the inclusive guarantee
	rootPkgs, err := packages.Load(cfg, "all")
	if err != nil {
		log.Debugf("error loading packages: %v", err)
	}

	// Check for any errors in loading
	for _, p := range rootPkgs {
		if len(p.Errors) > 0 {
			// Log errors but continue processing
			for _, e := range p.Errors {
				log.Debugf("package load error for %s: %v", p.PkgPath, e)
				unknownErr = unknown.Append(unknownErr, loc, err)
			}
		}
	}

	// note: dependencies have already pruned local imports and only focuses on module => module dependencies
	return c.visitPackages(rootPkgs, loc, unknownErr)
}

type pkgInfo struct {
	// pkgPath is the import path of the package.
	pkgPath string
	// modulePath is the module path of the package.
	modulePath string
	// pkgDir is the directory containing the package's source code.
	pkgDir string
	// moduleDir is the directory containing the module's source code.
	moduleDir string
}

// visitPackages processes Go module import graphs to get all modules
func (c *goModCataloger) visitPackages(
	rootPkgs []*packages.Package,
	loc file.Location,
	uke error,
) (pkgs map[string][]pkgInfo, modules map[string]*packages.Module, dependencies map[string][]string, unknownErr error) {
	modules = make(map[string]*packages.Module)
	// note: packages are specific to inside the module - they do not include transitive pkgInfo
	// packages is used for identifying licensing documents for modules that could contain multiple licenses
	// dependencies cover transitive module imports; see p.Imports array in packages.Visit
	pkgs = make(map[string][]pkgInfo)
	// dependencies are module => module dependencies
	dependencies = make(map[string][]string)
	// persist unknown errs from previous parts of the catalog
	unknownErr = uke
	// closure (p *Package) bool
	// return bool determines whether the imports of package p are visited.
	packages.Visit(rootPkgs, func(p *packages.Package) bool {
		if len(p.Errors) > 0 {
			for _, err := range p.Errors {
				unknownErr = unknown.Append(unknownErr, loc, err)
			}
			return false
		}

		// skip for common causes
		if shouldSkipVisit(p) {
			return false
		}

		// different from above; we still might want to visit imports
		// ignoring a package shouldn't end walking the tree
		// since we need to get the full picture for license discovery
		// for _, prefix := range c.config.IgnorePaths {
		//	if strings.HasPrefix(p.PkgPath, prefix) {
		//		return c.config.IncludeIgnoredDeps
		//	}
		//}
		pkgDir := resolvePkgDir(p)
		if pkgDir == "" {
			return true
		}

		module := newModule(p.Module)
		if module.Dir == "" {
			// We continue processing even when module.Dir is empty because we still want to:
			// 1. Extract module dependencies from p.Imports for dependency graph construction
			// 2. Create syft packages with available metadata (name, version, etc.)
			// 3. Build relationships between modules even without complete filesystem info
			// Not having the DIR here just means that we're not going to process the licenses

			// Common causes for module.Dir being empty:
			// - Vendored dependencies where Go toolchain loses some module metadata
			// - Replace directives pointing to non-existent or inaccessible paths
			// A known cause is that the module is vendored, so some information is lost.
			isVendored := strings.Contains(pkgDir, "/vendor/")
			if !isVendored {
				log.Debugf("module %s does not have dir and it's not vendored", module.Path)
			}
		}

		// extract module dependencies
		for _, imp := range p.Imports {
			if imp.Module != nil && imp.Module.Path != module.Path {
				if dependencies[module.Path] == nil {
					dependencies[module.Path] = []string{imp.Module.Path}
				} else {
					dependencies[module.Path] = append(dependencies[module.Path], imp.Module.Path)
				}
			}
		}

		info := pkgInfo{
			pkgPath:    p.PkgPath,
			modulePath: module.Path,
			pkgDir:     pkgDir,
			moduleDir:  module.Dir,
		}
		if !slices.Contains(pkgs[module.Path], info) { // avoid duplicates
			pkgs[module.Path] = append(pkgs[module.Path], info)
		}
		modules[p.Module.Path] = module

		return true
	}, nil)
	return pkgs, modules, dependencies, unknownErr
}

// create syft packages from Go modules found by the go toolchain
func (c *goModCataloger) catalogModules(
	ctx context.Context,
	scanRoot string,
	pkgs map[string][]pkgInfo,
	modules map[string]*packages.Module,
	reader file.LocationReadCloser,
	digests map[string]string,
) ([]pkg.Package, map[string]artifact.Identifiable) {
	syftPackages := make([]pkg.Package, 0)
	moduleToPackage := make(map[string]artifact.Identifiable)

	for _, m := range modules {
		if isRelativeImportOrMain(m.Path) {
			// relativeImport modules are already accounted for by their full module paths at other portions of syft's cataloging
			// example: something like ../../ found as a module for go.mod b, which is sub to go.mod a is accounted for
			// in another call to the goModCataloger when go.mod a is parsed
			// local modules that use a "main" heuristic, no module naming (sometimes common pre go module support)
			// are also not built as syft packages
			continue
		}

		pkgInfos := pkgs[m.Path]
		moduleLicenses := resolveModuleLicenses(ctx, scanRoot, pkgInfos, afero.NewOsFs())
		// we do out of source lookups for module parsing
		// locations are NOT included in the SBOM because of this
		goModulePkg := pkg.Package{
			Name:      m.Path,
			Version:   m.Version,
			Locations: file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			Licenses:  moduleLicenses,
			Language:  pkg.Go,
			Type:      pkg.GoModulePkg,
			PURL:      packageURL(m.Path, m.Version),
			Metadata:  createSourceMetadata(digests[fmt.Sprintf("%s %s", m.Path, m.Version)]),
		}
		goModulePkg.SetID()

		moduleToPackage[m.Path] = goModulePkg
		syftPackages = append(syftPackages, goModulePkg)
	}

	return syftPackages, moduleToPackage
}

// buildModuleRelationships creates artifact relationships between Go modules.
func buildModuleRelationships(
	syftPkgs []pkg.Package,
	dependencies map[string][]string,
	moduleToPkg map[string]artifact.Identifiable,
) []artifact.Relationship {
	var rels []artifact.Relationship
	seen := make(map[string]struct{})

	for _, fromPkg := range syftPkgs {
		for _, dep := range dependencies[fromPkg.Name] {
			if dep == fromPkg.Name {
				continue
			}
			toPkg, ok := moduleToPkg[dep]
			if !ok {
				continue
			}

			key := string(fromPkg.ID()) + string(toPkg.ID())
			if _, exists := seen[key]; exists {
				continue
			}

			rels = append(rels, artifact.Relationship{
				From: toPkg,   // dep
				To:   fromPkg, // parent
				Type: artifact.DependencyOfRelationship,
			})
			seen[key] = struct{}{}
		}
	}

	return rels
}

func (c *goModCataloger) parseModFileContents(reader file.LocationReadCloser) (*modfile.File, error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read go module: %w", err)
	}

	f, err := modfile.Parse(reader.RealPath, contents, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go module: %w", err)
	}

	return f, nil
}

// note this handles the deduplication from source by checking if the mod path exists in the sourceModules map
func (c *goModCataloger) createGoModPackages(ctx context.Context, resolver file.Resolver, modFile *modfile.File, sourceModules map[string]*packages.Module, reader file.LocationReadCloser, digests map[string]string) map[string]pkg.Package {
	goModPackages := make(map[string]pkg.Package)

	for _, m := range modFile.Require {
		if sourceModules == nil || sourceModules[m.Mod.Path] == nil {
			lics := c.licenseResolver.getLicenses(ctx, resolver, m.Mod.Path, m.Mod.Version)
			goModPkg := pkg.Package{
				Name:      m.Mod.Path,
				Version:   m.Mod.Version,
				Licenses:  pkg.NewLicenseSet(lics...),
				Locations: file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
				PURL:      packageURL(m.Mod.Path, m.Mod.Version),
				Language:  pkg.Go,
				Type:      pkg.GoModulePkg,
				Metadata: pkg.GolangModuleEntry{
					H1Digest: digests[fmt.Sprintf("%s %s", m.Mod.Path, m.Mod.Version)],
				},
			}
			goModPkg.SetID()
			goModPackages[m.Mod.Path] = goModPkg
		}
	}

	return goModPackages
}

// applyReplaceDirectives processes replace directives from go.mod
func (c *goModCataloger) applyReplaceDirectives(ctx context.Context, resolver file.Resolver, modFile *modfile.File, goModPackages map[string]pkg.Package, reader file.LocationReadCloser, digests map[string]string) {
	for _, m := range modFile.Replace {
		lics := c.licenseResolver.getLicenses(ctx, resolver, m.New.Path, m.New.Version)
		var finalPath string
		if !strings.HasPrefix(m.New.Path, ".") && !strings.HasPrefix(m.New.Path, "/") {
			finalPath = m.New.Path
			delete(goModPackages, m.Old.Path)
		} else {
			finalPath = m.Old.Path
		}
		goModPkg := pkg.Package{
			Name:      finalPath,
			Version:   m.New.Version,
			Licenses:  pkg.NewLicenseSet(lics...),
			Locations: file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:      packageURL(finalPath, m.New.Version),
			Language:  pkg.Go,
			Type:      pkg.GoModulePkg,
			Metadata: pkg.GolangModuleEntry{
				H1Digest: digests[fmt.Sprintf("%s %s", finalPath, m.New.Version)],
			},
		}
		goModPkg.SetID()
		goModPackages[finalPath] = goModPkg
	}
}

func (c *goModCataloger) applyExcludeDirectives(modFile *modfile.File, goModPackages map[string]pkg.Package) {
	for _, m := range modFile.Exclude {
		delete(goModPackages, m.Mod.Path)
	}
}

func (c *goModCataloger) assembleResults(catalogedPkgs []pkg.Package, goModPackages map[string]pkg.Package) []pkg.Package {
	pkgsSlice := make([]pkg.Package, 0)

	pkgsSlice = append(pkgsSlice, catalogedPkgs...)

	for _, p := range goModPackages {
		pkgsSlice = append(pkgsSlice, p)
	}

	pkg.Sort(pkgsSlice)

	return pkgsSlice
}

func parseGoSumFile(resolver file.Resolver, reader file.LocationReadCloser) (map[string]string, error) {
	out := map[string]string{}

	if resolver == nil {
		return out, fmt.Errorf("no resolver provided")
	}

	goSumPath := strings.TrimSuffix(reader.RealPath, ".mod") + ".sum"
	goSumLocation := resolver.RelativeFileByPath(reader.Location, goSumPath)
	if goSumLocation == nil {
		return nil, fmt.Errorf("unable to resolve: %s", goSumPath)
	}
	contents, err := resolver.FileContentsByLocation(*goSumLocation)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, goSumLocation.AccessPath)

	// go.sum has the format like:
	// github.com/BurntSushi/toml v0.3.1/go.mod h1:xHWCNGjB5oqiDr8zfno3MHue2Ht5sIBksp03qcyfWMU=
	// github.com/BurntSushi/toml v0.4.1 h1:GaI7EiDXDRfa8VshkTj7Fym7ha+y8/XxIgD2okUIjLw=
	// github.com/BurntSushi/toml v0.4.1/go.mod h1:CxXYINrC8qIiEnFrOxCa7Jy5BFHlXnUU2pbicEuybxQ=
	scanner := bufio.NewScanner(contents)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) < 3 {
			continue
		}
		nameVersion := fmt.Sprintf("%s %s", parts[0], parts[1])
		hash := parts[2]
		out[nameVersion] = hash
	}

	return out, nil
}

// createSourceMetadata creates metadata for packages found through source analysis using build.Default
func createSourceMetadata(h1Digest string) pkg.GolangSourceEntry {
	return pkg.GolangSourceEntry{
		H1Digest:        h1Digest,
		OperatingSystem: build.Default.GOOS,
		Architecture:    build.Default.GOARCH,
		BuildTags:       strings.Join(build.Default.BuildTags, ","),
		CgoEnabled:      build.Default.CgoEnabled,
	}
}

func resolvePkgDir(p *packages.Package) string {
	switch {
	case len(p.GoFiles) > 0:
		return filepath.Dir(p.GoFiles[0])
	case len(p.CompiledGoFiles) > 0:
		return filepath.Dir(p.CompiledGoFiles[0])
	case len(p.OtherFiles) > 0:
		return filepath.Dir(p.OtherFiles[0])
	default:
		return ""
	}
}

func shouldSkipVisit(p *packages.Package) bool {
	// skip packages that don't have module info
	if p.Module == nil {
		return true
	}

	// skip stdlib
	if isStdLib(p) {
		return true
	}

	return false
}

// isStdLib returns true if this package is part of the Go standard library.
func isStdLib(pkg *packages.Package) bool {
	if pkg.Name == "unsafe" {
		// Special case unsafe stdlib, because it does not contain go files.
		return true
	}
	if len(pkg.GoFiles) == 0 {
		return false
	}
	prefix := build.Default.GOROOT
	sep := string(filepath.Separator)
	if !strings.HasSuffix(prefix, sep) {
		prefix += sep
	}
	return strings.HasPrefix(pkg.GoFiles[0], prefix)
}

// handle replace directives
func newModule(mod *packages.Module) *packages.Module {
	// Example of a module with replace directive: 	k8s.io/kubernetes => k8s.io/kubernetes v1.11.1
	// {
	//         "Path": "k8s.io/kubernetes",
	//         "Version": "v0.17.9",
	//         "Replace": {
	//                 "Path": "k8s.io/kubernetes",
	//                 "Version": "v1.11.1",
	//                 "Time": "2018-07-17T04:20:29Z",
	//                 "Dir": "/home/gongyuan_kubeflow_org/go/pkg/mod/k8s.io/kubernetes@v1.11.1",
	//                 "GoMod": "/home/gongyuan_kubeflow_org/go/pkg/mod/cache/download/k8s.io/kubernetes/@v/v1.11.1.mod"
	//         },
	//         "Dir": "/home/gongyuan_kubeflow_org/go/pkg/mod/k8s.io/kubernetes@v1.11.1",
	//         "GoMod": "/home/gongyuan_kubeflow_org/go/pkg/mod/cache/download/k8s.io/kubernetes/@v/v1.11.1.mod"
	// }
	// handle replace directives
	// Note, we specifically want to replace version field.
	// Haven't confirmed, but we may also need to override the
	// entire struct when using replace directive with local folders.
	tmp := *mod
	if tmp.Replace != nil {
		tmp = *tmp.Replace
	}

	return &tmp
}

func isRelativeImportOrMain(p string) bool {
	if p == "main" {
		return true
	}
	// true for ".", "..", "./...", "../..."
	return build.IsLocalImport(p)
}
