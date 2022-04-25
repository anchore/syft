/*
Package conda provides a concrete Cataloger implementation for conda package .json files
within a given conda environment's conda-meta directory
*/
package conda

import (
    "fmt"
    //"github.com/anchore/syft/syft/pkg/cataloger/common"
    "github.com/anchore/syft/syft/artifact"
    "github.com/anchore/syft/syft/pkg"
    "github.com/anchore/syft/syft/source"
)

// TODO: add any additional useful conda files here such as history, recipes, etc.
const (
    condaMetaJSON = "**/conda-meta/*.json"
)

type CondaMetaCataloger struct{}

func NewCondaPackageCataloger() *CondaMetaCataloger {
    return &CondaMetaCataloger{}
}

func (c *CondaMetaCataloger) CondaMetaCatalog(resolver  source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
   var fileMatches []source.Location

   for _, glob := range []string{condaMetaJSON} {
       matches, err := resolver.FilesByGlob(glob)
       if err != nil {
           return nil, nil, fmt.Errorf("failed to find conda files by glob: %s", glob)
       }
       fileMatches = append(fileMatches, matches...)
    }

    var pkgs []pkg.Package
    //TODO: generate and add pkg.Package for each given conda-meta .json

    return pkgs, nil, nil
}


