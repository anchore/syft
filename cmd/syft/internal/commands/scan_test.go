package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/cmd/syft/internal/options"
)

func Test_scanOptions_validateLegacyOptionsNotUsed(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "no config file",
		},
		{
			name: "config file with no legacy options",
			cfg:  "test-fixtures/scan-configs/no-legacy-options.yaml",
		},
		{
			name:    "config file with default image pull source legacy option",
			cfg:     "test-fixtures/scan-configs/with-default-pull-source.yaml",
			wantErr: assertErrorContains("source.image.default-pull-source"),
		},
		{
			name:    "config file with exclude-binary-overlap-by-ownership legacy option",
			cfg:     "test-fixtures/scan-configs/with-exclude-binary-overlap-by-ownership.yaml",
			wantErr: assertErrorContains("package.exclude-binary-overlap-by-ownership"),
		},
		{
			name:    "config file with file string legacy option",
			cfg:     "test-fixtures/scan-configs/with-file-string.yaml",
			wantErr: assertErrorContains("outputs"),
		},
		{
			name: "config file with file section",
			cfg:  "test-fixtures/scan-configs/with-file-section.yaml",
		},
		{
			name:    "config file with base-path legacy option",
			cfg:     "test-fixtures/scan-configs/with-base-path.yaml",
			wantErr: assertErrorContains("source.base-path"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			o := &scanOptions{
				Config: options.Config{ConfigFile: tt.cfg},
			}
			tt.wantErr(t, o.validateLegacyOptionsNotUsed())
		})
	}
}

func assertErrorContains(contains string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, i ...interface{}) bool {
		return assert.ErrorContains(t, err, contains, i...)
	}
}
