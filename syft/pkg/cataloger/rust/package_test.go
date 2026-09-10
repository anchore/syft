package rust

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	type args struct {
		name    string
		version string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "go case",
			args: args{
				name:    "name",
				version: "v0.1.0",
			},
			want: "pkg:cargo/name@v0.1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, packageURL(tt.args.name, tt.args.version))
		})
	}
}

func TestNewPackageFromCargoMetadataPURL(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "crates.io package",
			source: "registry+https://github.com/rust-lang/crates.io-index",
			want:   "pkg:cargo/telemetry@0.1.0",
		},
		{
			name:   "local path package",
			source: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newPackageFromCargoMetadata(pkg.RustCargoLockEntry{
				Name:    "telemetry",
				Version: "0.1.0",
				Source:  tt.source,
			})

			assert.Equal(t, tt.want, got.PURL)
		})
	}
}
