/*
Package ai provides concrete Cataloger implementations for AI artifacts and machine learning models,
including support for GGUF (GPT-Generated Unified Format) model files.
*/
package ai

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewGGUFCataloger returns a new cataloger instance for GGUF model files.
func NewGGUFCataloger() pkg.Cataloger {
	return generic.NewCataloger("gguf-cataloger").
		WithParserByGlobs(parseGGUFModel, "**/*.gguf")
}
