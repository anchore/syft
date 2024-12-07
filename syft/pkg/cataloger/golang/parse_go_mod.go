package golang

import (
	"bufio"
	"context"
	"fmt"
	"golang.org/x/tools/go/packages"
	"io"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var searchSuffix = "/..."

type goModCataloger struct {
	licenseResolver goLicenseResolver
}

type goModSourceCataloger struct{}

func newGoModCataloger(opts CatalogerConfig) *goModCataloger {
	return &goModCataloger{
		licenseResolver: newGoLicenseResolver(modFileCatalogerName, opts),
	}
}

func newGoModSourceCataloger(opts CatalogerConfig) *goModSourceCataloger {
	return &goModSourceCataloger{}
}

func (c *goModSourceCataloger) parseGoModFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read module file: %w", err)
	}

	file, err := modfile.Parse("go.mod", contents, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse module file: %w", err)
	}

	// extract the module name and add the search suffix
	mainModuleName := file.Module.Mod.Path
	mainModuleName = fmt.Sprintf("%s%s", mainModuleName, searchSuffix)

	cfg := &packages.Config{
		Context: ctx,
		Mode:    packages.NeedImports | packages.NeedDeps | packages.NeedFiles | packages.NeedName | packages.NeedModule,
		Tests:   true,
	}

	rootPkgs, err := packages.Load(cfg, mainModuleName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load packages for %s: %w", mainModuleName, err)
	}

	syftPackages := make([]pkg.Package, 0)
	pkgErrorOccurred := false
	otherErrorOccurred := false
	packages.Visit(rootPkgs, func(p *packages.Package) bool {
		if len(p.Errors) > 0 {
			pkgErrorOccurred = true
			return false
		}
		if p.Module == nil {
			otherErrorOccurred = true
			return false
		}

		if !isValid(p) {
			return false
		}

		syftPackages = append(syftPackages, pkg.Package{
			Name:    p.Name,
			Version: p.Module.Version,
			// Licenses (TODO)
			// Locations: file.NewLocationSet(reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:     packageURL(p.PkgPath, p.Module.Version),
			Language: pkg.Go,
			Type:     pkg.GoModulePkg,
			Metadata: pkg.GolangModuleEntryMetadata{
				Path:      p.Module.Path,
				Version:   p.Module.Version,
				Replace:   p.Module.Replace,
				Time:      p.Module.Time,
				Main:      p.Module.Main,
				Indirect:  p.Module.Indirect,
				Dir:       p.Module.Dir,
				GoMod:     p.Module.GoMod,
				GoVersion: p.Module.GoVersion,
			},
		})
		return true
	}, nil)
	if pkgErrorOccurred {
		// TODO: log error as warning for packages that could not be analyzed
	}
	if otherErrorOccurred {
		// TODO: log errors for direct/transitive dependency loading
	}
	return syftPackages, nil, nil
}

func isValid(p *packages.Package) bool {
	if p.Name == "" {
		return false
	}
	if p.Module.Version == "" {
		return false
	}
	return true
}

// parseGoModFile takes a go.mod and lists all packages discovered.
//
//nolint:funlen
func (c *goModCataloger) parseGoModFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	packages := make(map[string]pkg.Package)

	licenseScanner := licenses.ContextLicenseScanner(ctx)

	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read go module: %w", err)
	}

	f, err := modfile.Parse(reader.RealPath, contents, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse go module: %w", err)
	}

	digests, err := parseGoSumFile(resolver, reader)
	if err != nil {
		log.Debugf("unable to get go.sum: %v", err)
	}

	for _, m := range f.Require {
		lics, err := c.licenseResolver.getLicenses(ctx, licenseScanner, resolver, m.Mod.Path, m.Mod.Version)
		if err != nil {
			log.Tracef("error getting licenses for package: %s %v", m.Mod.Path, err)
		}

		packages[m.Mod.Path] = pkg.Package{
			Name:      m.Mod.Path,
			Version:   m.Mod.Version,
			Licenses:  pkg.NewLicenseSet(lics...),
			Locations: file.NewLocationSet(reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:      packageURL(m.Mod.Path, m.Mod.Version),
			Language:  pkg.Go,
			Type:      pkg.GoModulePkg,
			Metadata: pkg.GolangModuleEntry{
				H1Digest: digests[fmt.Sprintf("%s %s", m.Mod.Path, m.Mod.Version)],
			},
		}
	}

	// remove any old packages and replace with new ones...
	for _, m := range f.Replace {
		lics, err := c.licenseResolver.getLicenses(ctx, licenseScanner, resolver, m.New.Path, m.New.Version)
		if err != nil {
			log.Tracef("error getting licenses for package: %s %v", m.New.Path, err)
		}

		// the old path and new path may be the same, in which case this is a noop,
		// but if they're different we need to remove the old package.
		delete(packages, m.Old.Path)

		packages[m.New.Path] = pkg.Package{
			Name:      m.New.Path,
			Version:   m.New.Version,
			Licenses:  pkg.NewLicenseSet(lics...),
			Locations: file.NewLocationSet(reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:      packageURL(m.New.Path, m.New.Version),
			Language:  pkg.Go,
			Type:      pkg.GoModulePkg,
			Metadata: pkg.GolangModuleEntry{
				H1Digest: digests[fmt.Sprintf("%s %s", m.New.Path, m.New.Version)],
			},
		}
	}

	// remove any packages from the exclude fields
	for _, m := range f.Exclude {
		delete(packages, m.Mod.Path)
	}

	pkgsSlice := make([]pkg.Package, len(packages))
	idx := 0
	for _, p := range packages {
		p.SetID()
		pkgsSlice[idx] = p
		idx++
	}

	sort.SliceStable(pkgsSlice, func(i, j int) bool {
		return pkgsSlice[i].Name < pkgsSlice[j].Name
	})

	return pkgsSlice, nil, nil
}

func parseGoSumFile(resolver file.Resolver, reader file.LocationReadCloser) (map[string]string, error) {
	out := map[string]string{}

	if resolver == nil {
		return out, fmt.Errorf("no resolver provided")
	}

	goSumPath := strings.TrimSuffix(reader.Location.RealPath, ".mod") + ".sum"
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
