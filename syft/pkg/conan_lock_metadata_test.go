package pkg

import "testing"

func TestConanLockMetadata_PackageURL(t *testing.T) {
	tests := []struct {
		name string
		m    ConanLockMetadata
		want string
	}{
		{
			name: "happy path",
			m: ConanLockMetadata{
				Ref: "farmerbrown5/3.13.9",
			},
			want: "pkg:conan/farmerbrown5@3.13.9",
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
