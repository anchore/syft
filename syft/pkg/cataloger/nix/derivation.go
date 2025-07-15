package nix

import (
	"fmt"
	"strings"

	"github.com/nix-community/go-nix/pkg/derivation"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
)

type derivationFile struct {
	Location file.Location
	derivation.Derivation
}

func newDerivationFromPath(p string, resolver file.Resolver) (*derivationFile, error) {
	locs, err := resolver.FilesByPath(p)
	if err != nil {
		return nil, fmt.Errorf("failed to find derivation: %w", err)
	}

	if len(locs) == 0 {
		return nil, nil
	}

	// only use one reference
	return newDerivationFromLocation(locs[0], resolver)
}

func newDerivationFromLocation(loc file.Location, resolver file.Resolver) (*derivationFile, error) {
	reader, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return nil, fmt.Errorf("failed to read derivation: %w", err)
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	d, err := derivation.ReadDerivation(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse derivation: %w", err)
	}

	return &derivationFile{
		Location:   loc,
		Derivation: *d,
	}, nil
}

type derivations struct {
	derivationsByDrvPath map[string]derivationFile
	drvPathByOutputPath  map[string]string
}

func newDerivations() *derivations {
	return &derivations{
		derivationsByDrvPath: make(map[string]derivationFile),
		drvPathByOutputPath:  make(map[string]string),
	}
}

func (c *derivations) add(df derivationFile) {
	c.derivationsByDrvPath[df.Location.RealPath] = df
	for _, output := range df.Outputs {
		if output == nil || output.Path == "" {
			continue
		}
		c.drvPathByOutputPath[output.Path] = df.Location.RealPath
	}
}

func (c *derivations) findDerivationForOutputPath(outputPath string) *derivationFile {
	if !strings.HasPrefix(outputPath, "/") {
		outputPath = "/" + outputPath
	}
	if drvPath, ok := c.drvPathByOutputPath[outputPath]; ok {
		d, ok := c.derivationsByDrvPath[drvPath]
		if ok {
			return &d
		}
	}
	return nil
}

// given a path as input, assuming it's an output path for a derivation, find all input store paths needed for this particular output path.
func (c *derivations) findDependencies(p string) []string {
	if d, ok := c.derivationsByDrvPath[p]; ok {
		var deps []string
		for drvPath, names := range d.InputDerivations {
			if len(names) == 0 {
				continue
			}
			for _, n := range names {
				outputPath := c.namedOutputStorePath(drvPath, n)
				if outputPath == "" {
					continue
				}
				deps = append(deps, outputPath)
			}
		}
		for _, inputSrc := range d.InputSources {
			if inputSrc == "" {
				continue
			}
			deps = append(deps, inputSrc)
		}
		return deps
	}
	if drvPath, ok := c.drvPathByOutputPath[p]; ok {
		return c.findDependencies(drvPath)
	}
	return nil
}

func (c *derivations) namedOutputStorePath(drvPath, name string) string {
	if d, ok := c.derivationsByDrvPath[drvPath]; ok {
		if output, ok := d.Outputs[name]; ok {
			return output.Path
		}
	}
	return ""
}
