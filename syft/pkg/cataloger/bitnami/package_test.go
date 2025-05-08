package bitnami

import (
	"reflect"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func Test_parseBitnamiPURL(t *testing.T) {
	tests := []struct {
		name    string
		purl    string
		want    *pkg.BitnamiSBOMEntry
		wantErr bool
	}{
		{
			name: "Valid Bitnami pURL",
			purl: "pkg:bitnami/redis@7.4.1-0?arch=arm64&distro=debian-12",
			want: &pkg.BitnamiSBOMEntry{
				Name:         "redis",
				Version:      "7.4.1",
				Revision:     "0",
				Architecture: "arm64",
				Distro:       "debian-12",
			},
			wantErr: false,
		},
		{
			name:    "Invalid pURL",
			purl:    "this/is/not/a/purl",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Invalid version",
			purl:    "pkg:bitnami/redis@7.4.1.0?arch=arm64&distro=debian-12",
			want:    nil,
			wantErr: true,
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			got, err := parseBitnamiPURL(test.purl)
			if (err != nil) != test.wantErr {
				tt.Errorf("parseBitnamiPURL() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if !reflect.DeepEqual(got, test.want) {
				tt.Errorf("parseBitnamiPURL() = %v, want %v", got, test.want)
			}
		})
	}
}
