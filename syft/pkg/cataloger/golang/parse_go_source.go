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
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var (
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|NOTICE).*$`)
)

type goSourceCataloger struct {
	includeTests bool
	// False is `givenImportPath` as the input to packages
	// True is only start on packages with Name `main` for the givenImportPath
	autoDetectEntry bool
	importPaths     []string
	ignorePaths     []string
	// true, we continue searching a branch even if dep ignored; good for license search
	// false, we cut the ignored path's branch off and skip all sub packages
	includeIgnoreDeps bool
}

// TODO: link opts to module resolvers for license search
func newGoSourceCataloger(_ CatalogerConfig) *goSourceCataloger {
	return &goSourceCataloger{}
}

// syft -o json dir:. => `./...` full application scan, multiple entrypoints
// syft -o json dir:./cmd/syft/main.go => `./cmd/syft/...` user knows where to start the import from
// entrypoint detection returns multiple mains for search
// we can't use the file.Resolver passed in here since the modules/license paths are outside the scan target
func (c *goSourceCataloger) parseGoSourceEntry(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) (pkgs []pkg.Package, rels []artifact.Relationship, err error) {
	// try to get precise module entrypoint before running the goSource analysis
	entrySearch := toImportSearchPattern(reader.Path())
	c.importPaths = append(c.importPaths, entrySearch)
	cfg := goSourceConfig{
		includeTests:      c.includeTests,
		autoDetectEntry:   c.autoDetectEntry,
		importPaths:       c.importPaths,
		ignorePaths:       c.ignorePaths,
		includeIgnoreDeps: c.includeIgnoreDeps,
	}
	return c.parseGoSource(ctx, cfg)
}

func toImportSearchPattern(mainFilePath string) string {
	dir := filepath.Dir(mainFilePath)
	return "./" + filepath.ToSlash(dir) + "/..."
}

type goSourceConfig struct {
	includeTests bool
	// False is `givenImportPath` as the input to packages
	// True is only start on packages with Name `main` for the givenImportPath
	autoDetectEntry bool
	importPaths     []string
	ignorePaths     []string
	// true, we continue searching a branch even if dep ignored; good for license search
	// false, we cut the ignored path's branch off and skip all sub packages
	includeIgnoreDeps bool
}

func (c *goSourceCataloger) parseGoSource(ctx context.Context, cfg goSourceConfig) (pkgs []pkg.Package, rels []artifact.Relationship, err error) {
	// import paths can look like ./...
	// this is different from something like ./github.com/anchore/syft/cmd/syft/...
	// the distinction here is cataloging an entire application vs a single entrypoint/module
	// when given a scope like ./... the goSource cataloger will try to select entry points for the search
	// see rootPkgs

	// resolved name version and the h1 digest name:version:h1digest
	// merge: locations are getting merged here
	// merge nodes that are the same so we don't have separate graphs for things imported.
	// It should be a merged graph for all the application being scanned.
	rootPkgs, err := loadPackages(ctx, cfg)
	if err != nil {
		return pkgs, rels, err
	}

	vendoredSearch := collectVendoredModules(rootPkgs)

	// we need allPkgs so we can perform a comprehensive license search
	// syft packages are created from modules
	allPkgs, allModules, allDependencies := visitPackages(cfg, rootPkgs, vendoredSearch)

	// get licenses and build go source packages
	// licenseScanner, _ := licenses.ContextLicenseScanner(ctx)
	syftPackages := make([]pkg.Package, 0)

	// modulePath => package
	moduleToPackage := make(map[string]artifact.Identifiable)
	for _, m := range allModules {
		pkgInfos := allPkgs[m.Path]
		moduleLicenses := pkg.NewLicenseSet()
		moduleLocations := file.NewLocationSet()
		for _, pkgInfo := range pkgInfos {
			moduleLocations.Add(file.NewLocation(pkgInfo.pkgPath))
			licenseResolver := fileresolver.NewFromUnindexedDirectory(pkgInfo.moduleDir)
			locations, err := findLicenseFileLocations(pkgInfo.pkgDir, pkgInfo.moduleDir)
			if err != nil {
				continue
			}
			for _, location := range locations {
				//nolint:gocritic
				// we don't want to stack 'defer' here we can just aggressively close
				contents, err := licenseResolver.FileContentsByLocation(location)
				if err != nil {
					continue
				}
				moduleLicenses.Add(pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(location, contents))...)
				contents.Close()
			}
		}

		// Only create packages for modules -
		// do NOT create individual syft packages for import paths
		goModulePkg := pkg.Package{
			Name:      m.Path,
			Version:   m.Version,
			FoundBy:   sourceCatalogerName,
			Locations: moduleLocations,
			Licenses:  moduleLicenses,
			Language:  pkg.Go,
			Type:      pkg.GoModulePkg, // Review: Do we need a new type?
			PURL:      packageURL(m.Path, m.Version),
			// Review: What, if anything, can we put for metadata here?
			// We could gather all the packages.Package info that make up the module
			// and merge it all as module metadata:
			// https://pkg.go.dev/golang.org/x/tools/go/packages#Package
		}
		goModulePkg.SetID()
		moduleToPackage[m.Path] = goModulePkg
		syftPackages = append(syftPackages, goModulePkg)
	}

	// build relationships now that packages have ID
	rels = make([]artifact.Relationship, 0)
	duplicates := make(map[string]struct{})
	for _, pkg := range syftPackages {
		moduleDependencies := allDependencies[pkg.Name]
		for _, module := range moduleDependencies {
			if module == pkg.Name {
				// we don't need to create relationships for same module
				continue
			}
			toPackage := moduleToPackage[module]
			if _, ok := duplicates[string(pkg.ID())+string(toPackage.ID())]; ok {
				continue
			}
			rels = append(rels, artifact.Relationship{
				From: pkg,
				To:   toPackage,
				Type: artifact.DependencyOfRelationship,
			})
			duplicates[string(pkg.ID())+string(toPackage.ID())] = struct{}{}
		}

	}

	return syftPackages, rels, nil
}

func loadPackages(ctx context.Context, cfg goSourceConfig) ([]*packages.Package, error) {
	pkgsCfg := &packages.Config{
		Context: ctx,
		// packages.NeedImports: needed for module imports
		// packages.NeedFiles: needed to try and get the LICENSE file for the package
		// packages.NeedName: needed to add the name and package path for package assembly
		// packages.NeedModule: need the module added in case entrypoint is not sibling location
		Mode:  packages.NeedImports | packages.NeedFiles | packages.NeedName | packages.NeedModule,
		Tests: cfg.includeTests,
	}
	pkgs, err := packages.Load(pkgsCfg, cfg.importPaths...)
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

func collectVendoredModules(pkgs []*packages.Package) []*packages.Module {
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

func visitPackages(
	cfg goSourceConfig,
	rootPkgs []*packages.Package,
	vendoredSearch []*packages.Module,
) (allPackages map[string][]pkgInfo, allModules map[string]*packages.Module, allDependencies map[string][]string) {
	allModules = make(map[string]*packages.Module)
	// note: these packages are specific to inside the module - they do not include transitive pkgInfo
	// these are used for identifying licensing documents that might be separate from a modules
	// top level license agreement
	// for transitive imports see p.Imports array in packages.Visit
	allPackages = make(map[string][]pkgInfo)
	// allDependencies are module => module dependencies
	allDependencies = make(map[string][]string)
	// closure (p *Package) bool
	// return bool determines whether the imports of package p are visited.
	packages.Visit(rootPkgs, func(p *packages.Package) bool {
		// skip for common causes
		if shouldSkipVisit(p, cfg.includeTests) {
			return false
		}

		// different from above; we still might want to visit imports
		// ignoring a package shouldn't end walking the tree
		// since we need to get the full picture for license discovery
		for _, prefix := range cfg.ignorePaths {
			if strings.HasPrefix(p.PkgPath, prefix) {
				return cfg.includeIgnoreDeps
			}
		}

		pkgDir := resolvePkgDir(p)
		if pkgDir == "" {
			// package is empty nothing to do
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
		for _, imp := range p.Imports {
			if imp.Module != nil && imp.Module.Path != module.Path {
				if allDependencies[module.Path] == nil {
					allDependencies[module.Path] = []string{imp.Module.Path}
				} else {
					allDependencies[module.Path] = append(allDependencies[module.Path], imp.Module.Path)
				}
			}
		}
		// p.PkgPath => pkgInfo && pkgIngo.modulePath => p.Module
		allPackages[module.Path] = append(allPackages[module.Path], pkgInfo{
			pkgPath:    p.PkgPath,
			modulePath: module.Path,
			pkgDir:     pkgDir,
			moduleDir:  module.Dir,
		})
		// Review: is this a correct assumption?
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

func findLicenseFileLocations(dir string, rootDir string) ([]file.Location, error) {
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

func findAllUpwards(dir string, r *regexp.Regexp, stopAt string) ([]file.Location, error) {
	var foundLocations []file.Location

	// Stop once we go out of the stopAt dir.
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
				// we build the resolver with the root as stopAt
				path = strings.TrimPrefix(path, stopAt)
				foundLocations = append(foundLocations, file.NewLocation(path))
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Can't go any higher up the directory tree.
			break
		}
		dir = parent
	}

	return foundLocations, nil
}
