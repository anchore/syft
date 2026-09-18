package githubactions

import (
	"testing"

	"github.com/anchore/packageurl-go"
)

func Test_packageURL_dockerUseStatements(t *testing.T) {
	digest := "sha256:527e78e6d29a9ac306e843cf766afe0604a0b35633f16913d85dd522218e8ca1"

	tests := []struct {
		name    string
		image   string
		version string
		want    string
	}{
		{
			name:    "digest-pinned image with tag",
			image:   "docker://ghcr.io/sethvargo/ratchet:latest",
			version: digest,
			want:    "pkg:oci/ratchet@sha256%3A527e78e6d29a9ac306e843cf766afe0604a0b35633f16913d85dd522218e8ca1?repository_url=ghcr.io%2Fsethvargo&tag=latest",
		},
		{
			name:    "tagged image without digest",
			image:   "docker://ghcr.io/sethvargo/ratchet:latest",
			version: "",
			want:    "pkg:oci/ratchet?repository_url=ghcr.io%2Fsethvargo&tag=latest",
		},
		{
			name:    "untagged image on default registry without digest has no identifying token",
			image:   "docker://ghcr.io/sethvargo/ratchet",
			version: "",
			want:    "",
		},
		{
			name:    "short image name with tag",
			image:   "docker://ubuntu:22.04",
			version: "",
			want:    "pkg:oci/ubuntu?tag=22.04",
		},
		{
			name:    "registry with port",
			image:   "docker://registry.example.com:5000/team/app:v1",
			version: "",
			want:    "pkg:oci/app?repository_url=registry.example.com%3A5000%2Fteam&tag=v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := packageURL(tt.image, tt.version)
			if got != tt.want {
				t.Errorf("packageURL() = %q, want %q", got, tt.want)
			}
			// any PURL we emit must round-trip through packageurl-go, otherwise
			// downstream consumers that parse it lose all identifying tokens
			if got != "" {
				if _, err := packageurl.FromString(got); err != nil {
					t.Errorf("packageURL() = %q, FromString failed: %v", got, err)
				}
			}
		})
	}
}
