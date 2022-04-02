package golang

import (
	"fmt"
	"io"
	"io/ioutil"
	"sort"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"golang.org/x/mod/modfile"
)

// parseGoMod takes a go.mod and lists all packages discovered.
func parseGoMod(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	packages := make(map[string]*pkg.Package)

	contents, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read go module: %w", err)
	}

	file, err := modfile.Parse(path, contents, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse go module: %w", err)
	}

	for _, m := range file.Require {
		packages[m.Mod.Path] = &pkg.Package{
			Name:     m.Mod.Path,
			Version:  m.Mod.Version,
			Language: pkg.Go,
			Type:     pkg.GoModulePkg,
		}
	}

	// remove any old packages and replace with new ones...
	for _, m := range file.Replace {
		packages[m.New.Path] = &pkg.Package{
			Name:     m.New.Path,
			Version:  m.New.Version,
			Language: pkg.Go,
			Type:     pkg.GoModulePkg,
		}
	}

	// remove any packages from the exclude fields
	for _, m := range file.Exclude {
		delete(packages, m.Mod.Path)
	}

	pkgsSlice := make([]*pkg.Package, len(packages))
	idx := 0
	for _, p := range packages {
		pkgsSlice[idx] = p
		idx++
	}

	sort.SliceStable(pkgsSlice, func(i, j int) bool {
		return pkgsSlice[i].Name < pkgsSlice[j].Name
	})

	return pkgsSlice, nil, nil
}
