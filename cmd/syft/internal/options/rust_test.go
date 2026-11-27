package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRustIncludeDevDependencies(t *testing.T) {
	cfg := DefaultCatalog()
	assert.True(t, cfg.ToPackagesConfig().Rust.IncludeDevDependencies)
	cfg.Rust.IncludeDevDependencies = false
	assert.False(t, cfg.ToPackagesConfig().Rust.IncludeDevDependencies)
}
