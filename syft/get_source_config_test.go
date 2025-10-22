package syft

import (
	"testing"

	"github.com/anchore/stereoscope"
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

	if len(providers) != len(allSourceProviders) {
		t.Errorf("Expected %d providers, got %d", len(allSourceProviders), len(providers))
	}
}

func TestGetProviders_Sources(t *testing.T) {
	userInput := ""
	cfg := &GetSourceConfig{Sources: []string{stereoscope.RegistryTag}}

	providers, err := cfg.getProviders(userInput)
	if err != nil {
		t.Errorf("Expected no error for Sources parameter, got: %v", err)
	}

	if len(providers) != 1 {
		t.Errorf("Expected 1 providers, got %d", len(providers))
	}
}
