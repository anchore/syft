package nix

import (
	"path"
	"strings"

	"github.com/nix-community/go-nix/pkg/derivation"
)

type derivationCollection struct {
	derivationsByDrvPath map[string]derivation.Derivation
	drvPathByOutputPath  map[string]string
}

func newDerivationCollection() *derivationCollection {
	return &derivationCollection{
		derivationsByDrvPath: make(map[string]derivation.Derivation),
		drvPathByOutputPath:  make(map[string]string),
	}
}

func (c *derivationCollection) add(p string, d *derivation.Derivation) {
	if d == nil {
		return
	}
	c.derivationsByDrvPath[p] = *d
	for _, output := range d.Outputs {
		if output == nil || output.Path == "" {
			continue
		}
		c.drvPathByOutputPath[output.Path] = p
	}
}

func (c *derivationCollection) findDerivationForOutput(outputPath string) string {
	if !strings.HasPrefix(outputPath, "/") {
		outputPath = "/" + outputPath
	}
	if drvPath, ok := c.drvPathByOutputPath[outputPath]; ok {
		// trim off any path and return the name of the derivation file relative to the store
		return path.Base(drvPath)
	}
	return ""
}

// given a path as input, assuming it's an output path for a derivation, find all input store paths needed for this particular output path.
func (c *derivationCollection) findDependencies(p string) []string {
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

func (c *derivationCollection) namedOutputStorePath(drvPath, name string) string {
	if d, ok := c.derivationsByDrvPath[drvPath]; ok {
		if output, ok := d.Outputs[name]; ok {
			return output.Path
		}
	}
	return ""
}
