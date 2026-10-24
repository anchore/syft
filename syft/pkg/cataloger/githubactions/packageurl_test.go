package githubactions

import "testing"

func Test_packageURL_skipsDockerPrefix(t *testing.T) {
	// docker:// references should return empty PURL (not a valid pkg:github)
	got := packageURL("docker://ghcr.io/sethvargo/ratchet:latest", "sha256:527e78e6d29a9ac306e843cf766afe0604a0b35633f16913d85dd522218e8ca1")
	if got != "" {
		t.Errorf("packageURL(digest-form) = %q, want empty string", got)
	}

	got = packageURL("docker://ghcr.io/some-org/some-action", "v1")
	if got != "" {
		t.Errorf("packageURL(tag-form) = %q, want empty string", got)
	}

	// Sanity: regular github actions still work
	got = packageURL("actions/checkout", "v4")
	want := "pkg:github/actions/checkout@v4"
	if got != want {
		t.Errorf("packageURL(regular) = %q, want %q", got, want)
	}
}
