package nix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_packageURL(t *testing.T) {

	tests := []struct {
		name      string
		storePath nixStorePath
		want      string
	}{
		{
			name: "name + version",
			storePath: nixStorePath{
				name:    "glibc",
				version: "2.34",
			},
			want: "pkg:nix/glibc@2.34",
		},
		{
			name: "hash qualifier",
			storePath: nixStorePath{
				name:       "glibc",
				version:    "2.34",
				outputHash: "h0cnbmfcn93xm5dg2x27ixhag1cwndga",
			},
			want: "pkg:nix/glibc@2.34?outputhash=h0cnbmfcn93xm5dg2x27ixhag1cwndga",
		},
		{
			name: "output qualifier",
			storePath: nixStorePath{
				name:       "glibc",
				version:    "2.34",
				outputHash: "h0cnbmfcn93xm5dg2x27ixhag1cwndga",
				output:     "bin",
			},
			want: "pkg:nix/glibc@2.34?output=bin&outputhash=h0cnbmfcn93xm5dg2x27ixhag1cwndga",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, packageURL(tt.storePath))
		})
	}
}
