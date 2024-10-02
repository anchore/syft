package python

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_parsePyvenvCfgReader(t *testing.T) {
	location := file.NewLocation("/some/bogus/path")

	tests := []struct {
		name    string
		fixture string
		want    *virtualEnvInfo
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "parse basic pyenv file",
			fixture: "test-fixtures/pyenv/good-config",
			want: &virtualEnvInfo{
				Location:                  location,
				Version:                   "3.9.5",
				IncludeSystemSitePackages: true,
			},
		},
		{
			name:    "trixy config cases",
			fixture: "test-fixtures/pyenv/trixy-config",
			want: &virtualEnvInfo{
				Location:                  location,
				Version:                   "3.3.3",
				IncludeSystemSitePackages: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			reader, err := os.Open(tt.fixture)
			require.NoError(t, err)

			got, err := parsePyvenvCfgReader(file.NewLocationReadCloser(location, reader))
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
