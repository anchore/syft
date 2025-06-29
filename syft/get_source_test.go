package syft

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

type mockSource struct {
	source.Source
	desc source.Description
}

func (s mockSource) Describe() source.Description {
	return s.desc
}

func TestValidateSourcePlatform_NilSource(t *testing.T) {
	cfg := &GetSourceConfig{
		SourceProviderConfig: &sourceproviders.Config{
			Platform: &image.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		},
	}

	err := validateSourcePlatform(nil, cfg)
	if err != nil {
		t.Errorf("Expected no error for nil source, got: %v", err)
	}
}

func TestValidateSourcePlatform_NilPlatformConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *GetSourceConfig
	}{
		{
			name: "nil config",
			cfg:  nil,
		},
		{
			name: "nil SourceProviderConfig",
			cfg: &GetSourceConfig{
				SourceProviderConfig: nil,
			},
		},
		{
			name: "nil Platform",
			cfg: &GetSourceConfig{
				SourceProviderConfig: &sourceproviders.Config{
					Platform: nil,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mockSource{
				desc: source.Description{
					Metadata: &source.ImageMetadata{},
				},
			}

			err := validateSourcePlatform(src, tt.cfg)
			if err != nil {
				t.Errorf("Expected no error for nil platform, got: %v", err)
			}
		})
	}
}

func TestValidateSourcePlatform_SupportedMetadataTypes(t *testing.T) {
	tracker := sourcemetadata.NewCompletionTester(t)
	cfg := &GetSourceConfig{
		SourceProviderConfig: &sourceproviders.Config{
			Platform: &image.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		},
	}

	tests := []struct {
		name     string
		metadata any
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "image",
			metadata: source.ImageMetadata{},
		},
		{
			name:     "snap",
			metadata: source.SnapMetadata{},
		},
		{
			name:     "dir",
			metadata: source.DirectoryMetadata{},
			wantErr:  require.Error,
		},
		{
			name:     "file",
			metadata: source.FileMetadata{},
			wantErr:  require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			tracker.Tested(t, tt.metadata)

			src := mockSource{
				desc: source.Description{
					Metadata: tt.metadata,
				},
			}

			err := validateSourcePlatform(src, cfg)
			tt.wantErr(t, err, "Expected no error for %s, got: %v", tt.name, err)
		})
	}
}

func TestValidateSourcePlatform_UnsupportedMetadataTypes(t *testing.T) {
	cfg := &GetSourceConfig{
		SourceProviderConfig: &sourceproviders.Config{
			Platform: &image.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		},
	}

	tests := []struct {
		name     string
		metadata interface{}
	}{
		{
			name:     "string metadata",
			metadata: "unsupported",
		},
		{
			name:     "int metadata",
			metadata: 42,
		},
		{
			name:     "nil metadata",
			metadata: nil,
		},
		{
			name:     "custom struct",
			metadata: struct{ Name string }{Name: "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := mockSource{
				desc: source.Description{
					Metadata: tt.metadata,
				},
			}

			err := validateSourcePlatform(src, cfg)
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}

			expectedMsg := "platform is not supported for this source type"
			if err.Error() != expectedMsg {
				t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
			}
		})
	}
}

func TestValidateSourcePlatform_ValidCombination(t *testing.T) {
	cfg := &GetSourceConfig{
		SourceProviderConfig: &sourceproviders.Config{
			Platform: &image.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		},
	}

	src := mockSource{
		desc: source.Description{
			Metadata: &source.ImageMetadata{},
		},
	}

	err := validateSourcePlatform(src, cfg)
	if err != nil {
		t.Errorf("Expected no error for valid combination, got: %v", err)
	}
}
