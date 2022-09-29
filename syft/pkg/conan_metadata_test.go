package pkg

import "testing"

func TestConanMetadata_PackageURL(t *testing.T) {
	tests := []struct {
		name string
		m    ConanMetadata
		want string
	}{
		{
			name: "happy path",
			m: ConanMetadata{
				Ref: "catch2/2.13.8",
			},
			want: "pkg:conan/catch2@2.13.8",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.m.PackageURL(nil); got != test.want {
				t.Errorf("ConanMetadata.PackageURL() = %v, want %v", got, test.want)
			}
		})
	}
}
