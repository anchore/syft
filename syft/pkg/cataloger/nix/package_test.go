package nix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_packageURL(t *testing.T) {

	tests := []struct {
		name      string
		storePath nixStorePath
		drvPath   string
		want      string
	}{
		{
			name: "name + version",
			storePath: nixStorePath{
				Name:    "glibc",
				Version: "2.34",
			},
			want: "pkg:nix/glibc@2.34",
		},
		{
			name: "hash qualifier",
			storePath: nixStorePath{
				Name:       "glibc",
				Version:    "2.34",
				OutputHash: "h0cnbmfcn93xm5dg2x27ixhag1cwndga",
			},
			want: "pkg:nix/glibc@2.34?outputhash=h0cnbmfcn93xm5dg2x27ixhag1cwndga",
		},
		{
			name: "output qualifier",
			storePath: nixStorePath{
				Name:       "glibc",
				Version:    "2.34",
				OutputHash: "h0cnbmfcn93xm5dg2x27ixhag1cwndga",
				Output:     "bin",
			},
			want: "pkg:nix/glibc@2.34?output=bin&outputhash=h0cnbmfcn93xm5dg2x27ixhag1cwndga",
		},
		{
			name: "derivation qualifier",
			storePath: nixStorePath{
				Name:    "glibc",
				Version: "2.34",
			},
			drvPath: "/nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34.drv",
			want:    "pkg:nix/glibc@2.34?drvpath=h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34.drv",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, packageURL(tt.storePath, tt.drvPath))
		})
	}
}
