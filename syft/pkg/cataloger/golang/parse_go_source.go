package golang

import (
	"context"
	"fmt"
	"go/build"
	"golang.org/x/mod/modfile"
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
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var (
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|README|NOTICE).*$`)
)

type goSourceCataloger struct {
	includeTests bool
	importPaths  []string
	ignorePaths  []string
}

func newGoSourceCataloger(opts CatalogerConfig) *goSourceCataloger {
	return &goSourceCataloger{}
}

// 3 modes
// syft -o json dir:. => `./...` full application scan, multiple entrypoints
// syft -o json dir:./cmd/syft/main.go => `./cmd/syft/...` user knows where to start the import from
// some middle ground or entrypoint detection?
func (c *goSourceCataloger) parseGoSourceEntry(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) (pkgs []pkg.Package, rels []artifact.Relationship, err error) {
	// try to get precise module entrypoint before running the goSource analysis
	entrySearch := toImportSearchPattern(reader.Location.Path())
	c.importPaths = append(c.importPaths, entrySearch)
	cfg := goSourceConfig{
		includeTests: c.includeTests,
		importPaths:  c.importPaths,
		ignoredPaths: c.ignorePaths,
	}
	return c.parseGoSource(ctx, cfg)
}

func toImportSearchPattern(mainFilePath string) string {
	dir := filepath.Dir(mainFilePath)
	return "./" + filepath.ToSlash(dir) + "/..."
}

func getModulePath(goModPath string) (*modfile.File, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	f, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, err
	}

	return f, nil
}

type goSourceConfig struct {
	includeTests bool
	importPaths  []string
	ignoredPaths []string
}

func (c *goSourceCataloger) parseGoSource(ctx context.Context, cfg goSourceConfig) (pkgs []pkg.Package, rels []artifact.Relationship, err error) {
	// import paths can look like ./...
	// this is different from something like ./github.com/anchore/syft/cmd/syft/...
	// the distinction here is application vs single entrypoint/module graphs
	// What are the config around discovering import paths? What are the correct defaults?
	// application sense or individual module sense?
	// TBD for more circumspect paths
	// detecting entrypoints or not?! We look for all entrypoints

	// resolved name version and the h1 digest name:version:h1digest
	// merge: locations are getting merged here
	// merge nodes that are the same so we don't have separate graphs for things imported.
	// It should be a merged graph for all the application being scanned.
	// are these different project trees or not?
	// anchore/syft go.mod => uuid@v1.0 => dependency X
	//                     => dependency X
	// anchore/syft/not-real go.mod => uuid@v1.0 => dependency X
	rootPkgs, err := loadPackages(ctx, cfg)
	if err != nil {
		return pkgs, rels, err
	}

	vendoredSearch := collectVendoredModules(rootPkgs)
	allPkgs, allModules, err := visitPackages(cfg, rootPkgs, vendoredSearch)
	if err != nil {
		return pkgs, rels, err
	}

	// get licenses and build go source packages
	// licenseScanner, _ := licenses.ContextLicenseScanner(ctx)
	pkgs = make([]pkg.Package, 0)
	for _, pkgInfo := range allPkgs {
		candidates, err := findLicenseFileCandidates(pkgInfo.pkgDir, pkgInfo.moduleDir)
		if err != nil {
			// no license, but we still want to build the package info
		}
		// TODO: add back in goroutine code for licenses
		fmt.Printf("found license file candidates: %+v\n", candidates)
		module := allModules[pkgInfo.modulePath]
		pkg := pkg.Package{
			Name:     pkgInfo.pkgPath,
			Version:  module.Version,
			FoundBy:  sourceCatalogerName,
			Language: pkg.Go,
			Type:     pkg.GoModulePkg, // Review: Do we need a new type?
		}
		pkgs = append(pkgs, pkg)
	}

	return pkgs, rels, nil
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
	return packages.Load(pkgsCfg, cfg.importPaths...)
}

func collectVendoredModules(pkgs []*packages.Package) []*Module {
	var result []*Module
	for _, pkg := range pkgs {
		if pkg.Module == nil {
			continue
		}

		module := newModule(pkg.Module)
		if module.Dir == "" {
			continue
		}

		result = append(result, module)
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
	vendoredSearch []*Module,
) (allPackages map[string]pkgInfo, allModules map[string]*Module, err error) {
	// boolean result of (p *Package) bool determines whether
	// the imports of package pkg are visited.
	allModules = make(map[string]*Module)
	allPackages = make(map[string]pkgInfo)
	packages.Visit(rootPkgs, func(p *packages.Package) bool {
		// skip for common causes
		if shouldSkipVisit(p, cfg.includeTests, cfg.ignoredPaths) {
			return false
		}

		// different from above since we still do want to visit imports
		// ignoring a package shouldn't end walking the tree
		for _, prefix := range cfg.ignoredPaths {
			if strings.HasPrefix(p.PkgPath, prefix) {
				return true
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
				// So the if condition above is already very strict for vendored packages.
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

		allPackages[p.PkgPath] = pkgInfo{
			pkgPath:    p.PkgPath,
			modulePath: module.Path,
			pkgDir:     pkgDir,
			moduleDir:  module.Dir,
		}
		allModules[module.Path] = module

		return true
	}, nil)
	return allPackages, allModules, nil
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

func shouldSkipVisit(p *packages.Package, includeTests bool, ignored []string) bool {
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
	module *Module
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
	min, max := paths[0], paths[len(paths)-1]
	lastSlashIndex := 0
	for i := 0; i < len(min) && i < len(max); i++ {
		if min[i] != max[i] {
			return min[:lastSlashIndex]
		}
		if min[i] == '/' {
			lastSlashIndex = i
		}
	}
	return min
}

// Module provides module information for a package.
type Module struct {
	// Differences from packages.Module:
	// * Replace field is removed, it's only an implementation detail in this package.
	//   If a module is replaced, we'll directly return the replaced module.
	// * Version field +incompatible suffix is trimmed.
	// * Main, ModuleError, Time, Indirect, GoMod, GoVersion fields are removed, because they are not used.
	Path    string // module path
	Version string // module version
	Dir     string // directory holding files for this module, if any
}

func newModule(mod *packages.Module) *Module {
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
	// TODO: This should be semver compliant and is ok for package constructors
	tmp.Version = strings.TrimSuffix(tmp.Version, "+incompatible")
	return &Module{
		Path:    tmp.Path,
		Version: tmp.Version,
		Dir:     tmp.Dir,
	}
}

func findLicenseFileCandidates(dir string, rootDir string) ([]string, error) {
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
	var foundPaths []string

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
				foundPaths = append(foundPaths, path)
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Can't go any higher up the directory tree.
			break
		}
		dir = parent
	}

	return foundPaths, nil
}
