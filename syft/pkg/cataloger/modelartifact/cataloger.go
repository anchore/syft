/*
Package modelartifact provides a concrete Cataloger implementation for detecting machine learning model artifacts.
*/
package modelartifact

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewCataloger returns a new cataloger for model artifacts based on config.json files
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger("model-artifact-cataloger").
		WithParserByGlobs(parseConfigJSON, "**/config.json")
}
