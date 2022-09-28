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
				Ref: "pkg/1.2.3@user/channel",
			},
			want: "pkg:conan/pkg@1.2.3",
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
