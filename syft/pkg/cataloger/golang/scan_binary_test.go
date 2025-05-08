package golang

import (
	"fmt"
	"io"
	"runtime/debug"
	"testing"

	"github.com/kastenhq/goversion/version"
	"github.com/stretchr/testify/assert"
)

func Test_getBuildInfo(t *testing.T) {
	type args struct {
		r io.ReaderAt
	}
	tests := []struct {
		name    string
		args    args
		wantBi  *debug.BuildInfo
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "recover from panic",
			args: args{
				r: nil, // trying to use a nil reader will cause a panic
			},
			wantBi:  nil, // we should not return anything useful
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBi, err := getBuildInfo(tt.args.r)
			if !tt.wantErr(t, err, fmt.Sprintf("getBuildInfo(%v)", tt.args.r)) {
				return
			}
			assert.Equalf(t, tt.wantBi, gotBi, "getBuildInfo(%v)", tt.args.r)
		})
	}
}

func Test_getCryptoSettingsFromVersion(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version version.Version
		result  []string
	}{
		{
			name: "standard crypto",
			version: version.Version{
				StandardCrypto: true,
			},
			result: []string{"standard-crypto"},
		},
		{
			name: "boring crypto",
			version: version.Version{
				BoringCrypto: true,
			},
			result: []string{"boring-crypto"},
		},
		{ // Should never see this. Boring crypto is required for fipsonly
			name: "fipsonly",
			version: version.Version{
				FIPSOnly: true,
			},
			result: []string{"crypto/tls/fipsonly"},
		},
		{
			name: "boring crypto and fipsonly",
			version: version.Version{
				BoringCrypto: true,
				FIPSOnly:     true,
			},
			result: []string{"boring-crypto", "crypto/tls/fipsonly"},
		},
		{ // Should never see this.
			name: "boring and standard crypto!",
			version: version.Version{
				BoringCrypto:   true,
				StandardCrypto: true,
			},
			result: []string{"boring-crypto", "standard-crypto"},
		},
		{ // Should never see this. Boring crypto is required for fipsonly
			name: "fipsonly and standard crypto!",
			version: version.Version{
				FIPSOnly:       true,
				StandardCrypto: true,
			},
			result: []string{"crypto/tls/fipsonly", "standard-crypto"},
		},

		{ // Should never see this. Boring crypto is required for fipsonly
			name: "fipsonly boringcrypto and standard crypto!",
			version: version.Version{
				FIPSOnly:       true,
				StandardCrypto: true,
				BoringCrypto:   true,
			},
			result: []string{"crypto/tls/fipsonly", "standard-crypto", "boring-crypto"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := getCryptoSettingsFromVersion(tt.version)
			assert.ElementsMatch(t, res, tt.result)
		})
	}
}
