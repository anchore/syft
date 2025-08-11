package golang

import (
	"bufio"
	"context"
	"fmt"
	"go/build"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var (
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|NOTICE).*$`)
)

type goModCataloger struct {
	licenseResolver goLicenseResolver
}

func newGoModCataloger(opts CatalogerConfig) *goModCataloger {
	return &goModCataloger{
		licenseResolver: newGoLicenseResolver(modFileCatalogerName, opts),
	}
}

// parseGoModFile takes a go.mod and lists all packages discovered.
//
//nolint:funlen
func (c *goModCataloger) parseGoModFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// Use RealPath for the actual filesystem path
	// note: this is OUTSIDE the source analysis and will NOT be used in the location list
	modDir := filepath.Dir(string(reader.Location.Reference().RealPath))

	// Parse go.sum file for digests
	digests, err := parseGoSumFile(resolver, reader)
	if err != nil {
		log.Debugf("unable to get go.sum: %v", err)
	}

	log.Debugf("attempting to load packages using Go toolchain for %s", reader.RealPath)
	syftSourcePackages, sourceModules, sourceDependencies := c.loadPackages(modDir)

	// combine source analysis with go.mod
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read go module: %w", err)
	}

	f, err := modfile.Parse(reader.RealPath, contents, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse go module: %w", err)
	}

	// Parse go.mod to fill in any missing packages from source results
	goModPackages := make(map[string]pkg.Package)
	for _, m := range f.Require {
		if _, exists := sourceModules[m.Mod.Path]; !exists {
			lics := c.licenseResolver.getLicenses(ctx, resolver, m.Mod.Path, m.Mod.Version)
			goModPackages[m.Mod.Path] = pkg.Package{
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
		}
	}

	// make sure replace directive is respected
	for _, m := range f.Replace {
		lics := c.licenseResolver.getLicenses(ctx, resolver, m.New.Path, m.New.Version)

		// the old path and new path may be the same, in which case this is a noop,
		// but if they're different we need to remove the old package.
		// note that we may change the path but we should always reference the new version (since the old version
		// cannot be trusted as a correct value).
		var finalPath string
		if !strings.HasPrefix(m.New.Path, ".") && !strings.HasPrefix(m.New.Path, "/") {
			finalPath = m.New.Path
			delete(goModPackages, m.Old.Path)
		} else {
			finalPath = m.Old.Path
		}
		goModPackages[finalPath] = pkg.Package{
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
	}

	// remove any packages from the exclude fields
	for _, m := range f.Exclude {
		delete(goModPackages, m.Mod.Path)
	}

	// let's finish cataloging our source packages
	catalogedPkgs, sourceModuleToPkg := c.catalogModules(ctx, syftSourcePackages, sourceModules, reader, digests)
	relationships := buildModuleRelationships(catalogedPkgs, sourceDependencies, sourceModuleToPkg)

	pkgsSlice := make([]pkg.Package, 0)
	for _, p := range catalogedPkgs {
		p.SetID()
		pkgsSlice = append(pkgsSlice, p)
	}

	for _, p := range goModPackages {
		p.SetID()
		pkgsSlice = append(pkgsSlice, p)
	}

	sort.SliceStable(pkgsSlice, func(i, j int) bool {
		return pkgsSlice[i].Name < pkgsSlice[j].Name
	})

	return pkgsSlice, relationships, nil
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

// loadPackages uses golang.org/x/tools/go/packages to get dependency information.
func (c *goModCataloger) loadPackages(modDir string) (pkgs map[string][]pkgInfo, modules map[string]*packages.Module, dependencies map[string][]string) {
	cfg := &packages.Config{
		Mode:  packages.NeedModule | packages.NeedName | packages.NeedFiles | packages.NeedDeps,
		Dir:   modDir,
		Tests: true,
	}

	// Load all packages for the given mod file
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
			}
		}
	}

	// - we need modulePkgImports so we can perform a comprehensive license search;
	// - syft packages are created from modules
	// - dependencies are a convenience that allows us to view pruned module => module imports;
	// note: dependencies have already pruned local imports and only focuses on module => module dependencies
	return c.visitPackages(rootPkgs)
}

// catalogModules creates syft packages from Go modules found by the toolchain.
func (c *goModCataloger) catalogModules(
	ctx context.Context,
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
		moduleLicenses := resolveModuleLicenses(ctx, pkgInfos)
		// we do out of source lookups for module parsing
		// locations are NOT included in the SBOM because of this
		goModulePkg := pkg.Package{
			Name:      m.Path,
			Version:   m.Version,
			Locations: file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			Licenses:  moduleLicenses,
			Language:  pkg.Go,
			Type:      pkg.GoSourcePkg,
			PURL:      packageURL(m.Path, m.Version),
			Metadata: pkg.GolangModuleEntry{
				H1Digest: digests[fmt.Sprintf("%s %s", m.Path, m.Version)],
			},
		}
		goModulePkg.SetID()

		moduleToPackage[m.Path] = goModulePkg
		syftPackages = append(syftPackages, goModulePkg)
	}

	return syftPackages, moduleToPackage
}

// resolveModuleLicenses finds and parses license files for Go modules.
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

// buildModuleRelationships creates artifact relationships between Go modules.
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
) (pkgs map[string][]pkgInfo, modules map[string]*packages.Module, dependencies map[string][]string) {
	modules = make(map[string]*packages.Module)
	// note: packages are specific to inside the module - they do not include transitive pkgInfo
	// packages is used for identifying licensing documents for modules that could contain multiple licenses
	// dependencies cover transitive module imports; see p.Imports array in packages.Visit
	pkgs = make(map[string][]pkgInfo)
	// dependencies are module => module dependencies
	dependencies = make(map[string][]string)
	// closure (p *Package) bool
	// return bool determines whether the imports of package p are visited.
	packages.Visit(rootPkgs, func(p *packages.Package) bool {
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
			// A known cause is that the module is vendored, so some information is lost.
			isVendored := strings.Contains(pkgDir, "/vendor/")
			if !isVendored {
				log.Warnf("module %s does not have dir and it's not vendored", module.Path)
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
		pkgs[module.Path] = append(pkgs[module.Path], pkgInfo{
			pkgPath:    p.PkgPath,
			modulePath: module.Path,
			pkgDir:     pkgDir,
			moduleDir:  module.Dir,
		})
		modules[p.Module.Path] = module

		return true
	}, nil)
	return pkgs, modules, dependencies
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
	// skip packages with errors
	if len(p.Errors) > 0 {
		return true
	}

	// skip packages that don't have module info
	if p.Module == nil {
		// log.Warnf("Package %s does not have module info. Non go modules projects are no longer supported.", p.PkgPath)
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

func isRelativeImportOrMain(p string) bool {
	if p == "main" {
		return true
	}
	// true for ".", "..", "./...", "../..."
	return build.IsLocalImport(p)
}
