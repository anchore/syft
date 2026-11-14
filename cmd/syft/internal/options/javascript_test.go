package options

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJavaScriptLocalLicenses(t *testing.T) {
	cfg := DefaultCatalog()
	require.True(t, cfg.JavaScript.SearchLocalLicenses)
	require.True(t, cfg.ToPackagesConfig().JavaScript.SearchLocalLicenses)
	cfg.JavaScript.SearchLocalLicenses = false
	require.False(t, cfg.ToPackagesConfig().JavaScript.SearchLocalLicenses)
	// Remote enrichment must not re-enable local file discovery.
	cfg.Enrich = []string{"javascript"}
	require.False(t, cfg.ToPackagesConfig().JavaScript.SearchLocalLicenses)
	require.True(t, cfg.ToPackagesConfig().JavaScript.SearchRemoteLicenses)
}
