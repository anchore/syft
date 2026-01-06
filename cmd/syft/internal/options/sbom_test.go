package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSBOMConfig_PostLoad(t *testing.T) {
	tests := []struct {
		name    string
		authors []string
		assert  func(t *testing.T, cfg SBOMConfig)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "parses multiple authors",
			authors: []string{"type=person&name=Alice&email=alice@example.com", "type=organization&name=ACME Inc"},
			assert: func(t *testing.T, cfg SBOMConfig) {
				assert.Len(t, cfg.GetAuthors(), 2)
				assert.Equal(t, "person", cfg.GetAuthors()[0].Type)
				assert.Equal(t, "Alice", cfg.GetAuthors()[0].Name)
			},
		},
		{
			name:    "normalizes type to lowercase",
			authors: []string{"type=PERSON&name=Bob"},
			assert: func(t *testing.T, cfg SBOMConfig) {
				assert.Equal(t, "person", cfg.GetAuthors()[0].Type)
			},
		},
		{
			name:    "rejects invalid type",
			authors: []string{"type=invalid&name=Bob"},
			wantErr: assert.Error,
		},
		{
			name:    "accepts all valid types",
			authors: []string{"type=person&name=Alice", "type=organization&name=ACME", "type=tool&name=Builder"},
			assert: func(t *testing.T, cfg SBOMConfig) {
				assert.Len(t, cfg.GetAuthors(), 3)
				assert.Equal(t, "person", cfg.GetAuthors()[0].Type)
				assert.Equal(t, "organization", cfg.GetAuthors()[1].Type)
				assert.Equal(t, "tool", cfg.GetAuthors()[2].Type)
			},
		},
		{
			name:    "missing required fields",
			authors: []string{"type=person"},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			cfg := SBOMConfig{Authors: tt.authors}
			tt.wantErr(t, cfg.PostLoad())
			if tt.assert != nil {
				tt.assert(t, cfg)
			}
		})
	}
}

func TestParseActor(t *testing.T) {
	actor, err := parseActor("type=person&name=Charlie&email=charlie@test.org")
	require.NoError(t, err)
	assert.Equal(t, "person", actor.Type)
	assert.Equal(t, "Charlie", actor.Name)
	assert.Equal(t, "charlie@test.org", actor.Email)
}
