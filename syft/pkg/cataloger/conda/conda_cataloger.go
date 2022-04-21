/*
Package conda provides a concrete Cataloger implementation for conda package .json files
within a given conda environment's conda-meta directory
*/
package conda

import (
    "github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewCondaMetaCataloger returns a new conda-meta cataloger object
func NewCondaMetaCataloger() *common.GenericCataloger {
    globParsers := map[string]common.ParserFn{
        "**/conda-meta/*.json": parseCondaMeta,
    }

    return common.NewGenericCataloger(nil, globParsers, "conda-cataloger")
}
