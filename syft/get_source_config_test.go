package syft

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

func TestGetProviders_DefaultImagePullSource(t *testing.T) {
	userInput := ""
	cfg := &GetSourceConfig{DefaultImagePullSource: stereoscope.RegistryTag}
	allSourceProviders := sourceproviders.All(userInput, cfg.SourceProviderConfig)

	providers, err := cfg.getProviders(userInput)
	if err != nil {
		t.Errorf("Expected no error for DefaultImagePullSource parameter, got: %v", err)
	}

	// everything except containers-storage, which is only used when requested by name
	if len(providers) != len(allSourceProviders)-1 {
		t.Errorf("Expected %d providers, got %d", len(allSourceProviders)-1, len(providers))
	}
}

func TestGetProviders_Sources(t *testing.T) {
	userInput := ""
	cfg := &GetSourceConfig{Sources: []string{stereoscope.RegistryTag}}

	providers, err := cfg.getProviders(userInput)
	if err != nil {
		t.Errorf("Expected no error for Sources parameter, got: %v", err)
	}

	// Registry tag has two providers: OCIModel and Image
	if len(providers) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(providers))
	}
}

func TestGetProviders_ContainersStorageOnlyWhenRequested(t *testing.T) {
	const storage = image.ContainersStorageSource

	tests := []struct {
		name      string
		cfg       *GetSourceConfig
		wantFound bool
		// if set, containers-storage must be ordered ahead of this provider
		wantBefore string
	}{
		{
			name: "excluded from automatic resolution",
			cfg:  DefaultGetSourceConfig(),
		},
		{
			name: "excluded when selecting all pull sources",
			cfg:  DefaultGetSourceConfig().WithSources(sourceproviders.PullTag),
		},
		{
			name: "excluded when a different default pull source is set",
			cfg:  DefaultGetSourceConfig().WithDefaultImagePullSource(stereoscope.RegistryTag),
		},
		{
			name:      "included when explicitly selected",
			cfg:       DefaultGetSourceConfig().WithSources(storage),
			wantFound: true,
		},
		{
			name:       "included ahead of other pull sources when it is the default pull source",
			cfg:        DefaultGetSourceConfig().WithDefaultImagePullSource(storage),
			wantFound:  true,
			wantBefore: image.DockerDaemonSource,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providers, err := tt.cfg.getProviders("localhost/myimage:latest")
			require.NoError(t, err)
			require.NotEmpty(t, providers)

			assert.Equal(t, tt.wantFound, providerIndex(providers, storage) >= 0)
			if tt.wantBefore != "" {
				assert.Less(t, providerIndex(providers, storage), providerIndex(providers, tt.wantBefore))
			}
		})
	}
}

func providerIndex(providers []source.Provider, name string) int {
	return slices.IndexFunc(providers, func(p source.Provider) bool { return p.Name() == name })
}
