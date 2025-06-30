package golang

import (
	"context"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const (
	goModGlob = "**/go.mod"
)

var (
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|NOTICE).*$`)
)

type goSourceCataloger struct {
	config GoSourceConfig
}

type ResolverResolutionPath interface {
	ResolverResolutionPath() string
}

func (c goSourceCataloger) Name() string { return sourceCatalogerName }

func (c goSourceCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	upperMost, err := findSearchPath(resolver)
	if err != nil {
		return nil, nil, err
	}
	c.config.ImportPaths = append(c.config.ImportPaths, "./...")
	c.config.Dir = upperMost
	return c.parseGoSourceEntry(ctx)
}

func findSearchPath(resolver file.Resolver) (importPath string, err error) {
	locs, err := resolver.FilesByGlob(goModGlob)
	if err != nil {
		return importPath, fmt.Errorf("unable to find go.mod files: %w", err)
	}
	var upperMost file.Location
	minDepth := -1
	for _, loc := range locs {
		path := loc.RealPath
		dir := filepath.Dir(filepath.Clean(path))
		depth := len(strings.Split(dir, string(filepath.Separator)))
		if minDepth == -1 || depth < minDepth {
			minDepth = depth
			upperMost = loc
		}
	}

	// solving for golang package searchPath
	// we use the resolver here since it already solves for config.source.base-path
	// example: user input of  dir:./some/things/go.mod
	// ./go.mod <-- resolver would return when searching for go.mod
	// so we want ./some/things/... as the search path
	// we need to square where the resolver is finding the go.mod with where syft is running
	// we could also be given
	// a/b/c/go.mod
	// with base config given a/b
	// c/go.mod  comes back from the resolver
	// ./c/... we want this as the search path
	absPath := upperMost.Reference().RealPath
	if err != nil {
		return importPath, fmt.Errorf("unable to find go.mod file metadata: %w", err)
	}
	return filepath.Dir(string(absPath)), nil
}

func newGoSourceCataloger(cfg CatalogerConfig) *goSourceCataloger {
	return &goSourceCataloger{
		config: cfg.GoSourceConfig,
	}
}

// syft -o json dir:. => `./...` full application scan, multiple entrypoints
// syft -o json dir:./cmd/syft/main.go => `./cmd/syft/...` user knows where to start the import from
// cataloger can return multiple mains for search
// we can't use the file.Resolver passed in here since the modules/license paths are sometimes outside the scan target
func (c goSourceCataloger) parseGoSourceEntry(ctx context.Context) (pkgs []pkg.Package, rels []artifact.Relationship, err error) {
	// cfg.importPaths can look like ./...
	// ./... is different from something like ./github.com/anchore/syft/cmd/syft/...
	// the distinction here is cataloging an entire application vs a single entrypoint/module
	// when given a scope like ./... the goSource cataloger will try to select the entry points for the search
	rootPkgs, err := c.loadPackages(ctx)
	if err != nil {
		return pkgs, rels, err
	}
	rootModules := filterNoModules(rootPkgs)

	// - we need allModulePkgImports so we can perform a comprehensive license search;
	// - syft packages are created from allModules
	// - allDependencies is a convenience that allows us to view pruned module => module imports;
	// note: allDependencies has already pruned local imports and only focuses on module => module dependencies
	allModulePkgImports, allModules, allDependencies := c.visitPackages(rootPkgs, rootModules)

	pkgs, moduleToPkg := c.catalogModules(ctx, allModulePkgImports, allModules)
	rels = buildModuleRelationships(pkgs, allDependencies, moduleToPkg)
	return pkgs, rels, nil
}

func (c *goSourceCataloger) catalogModules(
	ctx context.Context,
	allPkgs map[string][]pkgInfo,
	allModules map[string]*packages.Module,
) ([]pkg.Package, map[string]artifact.Identifiable) {
	syftPackages := make([]pkg.Package, 0)
	moduleToPackage := make(map[string]artifact.Identifiable)

	for _, m := range allModules {
		pkgInfos := allPkgs[m.Path]
		moduleLicenses := resolveModuleLicenses(ctx, pkgInfos)
		// we do out of source lookups for module parsing
		// locations are NOT included in the SBOM because of this
		goModulePkg := pkg.Package{
			Name:      m.Path,
			Version:   m.Version,
			FoundBy:   sourceCatalogerName,
			Locations: file.NewLocationSet(),
			Licenses:  moduleLicenses,
			Language:  pkg.Go,
			Type:      pkg.GoSourcePkg,
			PURL:      packageURL(m.Path, m.Version),
		}
		goModulePkg.SetID()

		moduleToPackage[m.Path] = goModulePkg
		syftPackages = append(syftPackages, goModulePkg)
	}

	return syftPackages, moduleToPackage
}

func resolveModuleLicenses(ctx context.Context, pkgInfos []pkgInfo) pkg.LicenseSet {
	licenses := pkg.NewLicenseSet()

	for _, info := range pkgInfos {
		licenseFiles, err := findLicenseFileLocations(info.pkgDir, info.moduleDir)
		if err != nil {
			continue
		}

		for _, f := range licenseFiles {
			contents, err := os.Open(f)
			if err != nil {
				continue
			}
			licenses.Add(pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(file.Location{}, contents))...)
			_ = contents.Close()
		}
	}

	return licenses
}

func buildModuleRelationships(
	syftPkgs []pkg.Package,
	dependencies map[string][]string,
	moduleToPkg map[string]artifact.Identifiable,
) []artifact.Relationship {
	rels := make([]artifact.Relationship, 0)
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

func (c *goSourceCataloger) loadPackages(ctx context.Context) ([]*packages.Package, error) {
	pkgsCfg := &packages.Config{
		Context: ctx,
		// packages.NeedImports: needed to read module imports and build pkg import graph
		// packages.NeedFiles: needed to try and get the LICENSE file for the package
		// packages.NeedName: needed to add the name and package path for package assembly
		// packages.NeedModule: need the module added in case entrypoint is not sibling location
		Mode:  packages.NeedImports | packages.NeedFiles | packages.NeedName | packages.NeedModule,
		Dir:   c.config.Dir,
		Tests: c.config.IncludeTests,
	}
	pkgs, err := packages.Load(pkgsCfg, c.config.ImportPaths...)
	if err != nil {
		return nil, err
	}
	filtered := pkgs[:0]
	for _, pkg := range pkgs {
		if pkg.Name != "main" {
			continue
		}
		filtered = append(filtered, pkg)
	}
	return filtered, nil
}

func filterNoModules(pkgs []*packages.Package) []*packages.Module {
	var result []*packages.Module
	for _, pkg := range pkgs {
		if pkg.Module == nil {
			// we can't grab modules from a package that has no module information
			continue
		}

		result = append(result, pkg.Module)
	}
	return result
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

//nolint:gocognit
func (c *goSourceCataloger) visitPackages(
	rootPkgs []*packages.Package,
	vendoredSearch []*packages.Module,
) (allPackages map[string][]pkgInfo, allModules map[string]*packages.Module, allDependencies map[string][]string) {
	allModules = make(map[string]*packages.Module)
	// note: allPackages are specific to inside the module - they do not include transitive pkgInfo
	// allPackages is used for identifying licensing documents for modules that could contain multiple licenses
	// allDependencies cover transitive module imports; see p.Imports array in packages.Visit
	allPackages = make(map[string][]pkgInfo)
	// allDependencies are module => module dependencies
	allDependencies = make(map[string][]string)
	// closure (p *Package) bool
	// return bool determines whether the imports of package p are visited.
	packages.Visit(rootPkgs, func(p *packages.Package) bool {
		// skip for common causes
		if shouldSkipVisit(p, c.config.IncludeTests) {
			return false
		}

		// different from above; we still might want to visit imports
		// ignoring a package shouldn't end walking the tree
		// since we need to get the full picture for license discovery
		for _, prefix := range c.config.IgnorePaths {
			if strings.HasPrefix(p.PkgPath, prefix) {
				return c.config.IncludeIgnoredDeps
			}
		}

		pkgDir := resolvePkgDir(p)
		if pkgDir == "" {
			return true
		}

		if len(p.OtherFiles) > 0 {
			log.Warnf("%q contains non-Go code that can't be inspected for further dependencies:\n%s", p.PkgPath, strings.Join(p.OtherFiles, "\n"))
		}

		module := newModule(p.Module)
		if module.Dir == "" {
			// A known cause is that the module is vendored, so some information is lost.
			isVendored := strings.Contains(pkgDir, "/vendor/")
			if !isVendored {
				log.Warnf("module %s does not have dir and it's not vendored", module.Path)
			} else {
				// This is vendored. Handle this known special case.

				// For a normal package:
				// * if it's not in a module, lib.module == nil
				// * if it's in a module, lib.module.Dir != ""
				// Only vendored modules will have lib.module != nil && lib.module.Path != "" && lib.module.Dir == ""
				// So the condition above is already very strict for vendored packages.
				for _, parentModule := range vendoredSearch {
					if strings.HasPrefix(pkgDir, parentModule.Dir) {
						module = parentModule
						break
					}
				}

				if module.Dir == "" {
					log.Warnf("cannot find parent package of vendored module %s", module.Path)
				}
			}
		}

		// extract module dependencies
		for _, imp := range p.Imports {
			if imp.Module != nil && imp.Module.Path != module.Path {
				if allDependencies[module.Path] == nil {
					allDependencies[module.Path] = []string{imp.Module.Path}
				} else {
					allDependencies[module.Path] = append(allDependencies[module.Path], imp.Module.Path)
				}
			}
		}
		allPackages[module.Path] = append(allPackages[module.Path], pkgInfo{
			pkgPath:    p.PkgPath,
			modulePath: module.Path,
			pkgDir:     pkgDir,
			moduleDir:  module.Dir,
		})
		allModules[p.Module.Path] = module

		return true
	}, nil)
	return allPackages, allModules, allDependencies
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

func shouldSkipVisit(p *packages.Package, includeTests bool) bool {
	// skip packages with errors
	if len(p.Errors) > 0 {
		return true
	}

	// skip packages that don't have module info
	if p.Module == nil {
		log.Warnf("Package %s does not have module info. Non go modules projects are no longer supported.", p.PkgPath)
		return true
	}

	// skip stdlib
	if isStdLib(p) {
		return true
	}

	// skip tests given user input
	if !includeTests && isTestBinary(p) {
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

// isTestBinary returns true iff pkg is a test binary.
func isTestBinary(pkg *packages.Package) bool {
	return strings.HasSuffix(pkg.PkgPath, ".test")
}

type Library struct {
	// Packages contain import paths for Go packages in this library.
	// It may not be the complete set of all packages in the library.
	Packages []string
	// Parent go module.
	module *packages.Module
}

// Name is the common prefix of the import paths for all of the packages in this library.
func (l *Library) Name() string {
	return commonAncestor(l.Packages)
}

func (l *Library) String() string {
	return l.Name()
}

func (l *Library) Version() string {
	if l.module != nil {
		return l.module.Version
	}
	return ""
}

func commonAncestor(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	if len(paths) == 1 {
		return paths[0]
	}
	sort.Strings(paths)
	small, large := paths[0], paths[len(paths)-1]
	lastSlashIndex := 0
	for i := 0; i < len(small) && i < len(large); i++ {
		if small[i] != large[i] {
			return small[:lastSlashIndex]
		}
		if small[i] == '/' {
			lastSlashIndex = i
		}
	}
	return small
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

	// The +incompatible suffix does not affect module version.
	// ref: https://golang.org/ref/mod#incompatible-versions
	tmp.Version = strings.TrimSuffix(tmp.Version, "+incompatible")
	return &tmp
}

func findLicenseFileLocations(dir string, rootDir string) ([]string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	rootDir, err = filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(dir, rootDir) {
		return nil, fmt.Errorf("licenses.Find: rootDir %s should contain dir %s", rootDir, dir)
	}

	return findAllUpwards(dir, licenseRegexp, rootDir)
}

func findAllUpwards(dir string, r *regexp.Regexp, stopAt string) ([]string, error) {
	// Stop once we go out of the stopAt dir.
	licenseCandidates := make([]string, 0)
	for strings.HasPrefix(dir, stopAt) {
		dirContents, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}

		for _, f := range dirContents {
			if f.IsDir() {
				continue
			}

			if r.MatchString(f.Name()) {
				path := filepath.Join(dir, f.Name())
				licenseCandidates = append(licenseCandidates, path)
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Can't go any higher up the directory tree.
			break
		}
		dir = parent
	}

	return licenseCandidates, nil
}
