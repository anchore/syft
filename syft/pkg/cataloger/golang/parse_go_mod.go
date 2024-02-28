package golang

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type goModCataloger struct {
	licenses goLicenses
}

// parseGoModFile takes a go.mod and lists all packages discovered.
//
//nolint:funlen
func (c *goModCataloger) parseGoModFile(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	packages := make(map[string]pkg.Package)

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
		licenses, err := c.licenses.getLicenses(resolver, m.Mod.Path, m.Mod.Version)
		if err != nil {
			log.Tracef("error getting licenses for package: %s %v", m.Mod.Path, err)
		}

		packages[m.Mod.Path] = pkg.Package{
			Name:      m.Mod.Path,
			Version:   m.Mod.Version,
			Licenses:  pkg.NewLicenseSet(licenses...),
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
		licenses, err := c.licenses.getLicenses(resolver, m.New.Path, m.New.Version)
		if err != nil {
			log.Tracef("error getting licenses for package: %s %v", m.New.Path, err)
		}

		packages[m.New.Path] = pkg.Package{
			Name:      m.New.Path,
			Version:   m.New.Version,
			Licenses:  pkg.NewLicenseSet(licenses...),
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
