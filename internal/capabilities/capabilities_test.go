package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDocument(t *testing.T) {
	doc, err := LoadDocument()
	require.NoError(t, err)
	require.NotNil(t, doc)

	// validate application config is loaded
	assert.NotEmpty(t, doc.ApplicationConfig, "should have application config")

	// validate catalogers are loaded and merged from all packages/*.yaml files
	assert.NotEmpty(t, doc.Catalogers, "should have catalogers")
	assert.Greater(t, len(doc.Catalogers), 50, "should have at least 50 catalogers")

	// validate configs are loaded
	assert.NotEmpty(t, doc.Configs, "should have configs")

	// check that catalogers are sorted by name
	for i := 1; i < len(doc.Catalogers); i++ {
		assert.LessOrEqual(t, doc.Catalogers[i-1].Name, doc.Catalogers[i].Name,
			"catalogers should be sorted by name")
	}
}

func TestPackages(t *testing.T) {
	catalogers, err := Packages()
	require.NoError(t, err)
	require.NotNil(t, catalogers)

	assert.Greater(t, len(catalogers), 50, "should have at least 50 catalogers")
}
