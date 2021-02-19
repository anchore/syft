package file

import (
	"github.com/spf13/afero"
	"testing"
)

func TestValidateByHash(t *testing.T) {
	var tests = []struct {
		path     string
		checksum string
		valid    bool
		err      bool
	}{
		{"test-fixtures/zip-source/b-file.txt", "sha256:875aa6bf2b0a7bf0635fd9067a7a24945f3a50d7c0c835117ad3ce315a1d132d", true, false},
		{"test-fixtures/zip-source/b-file.txt", "sha256:fcb3211e1ed7d82a2c1822fa4d65cbe75c2b1e9b2b537d82049557836e578271", false, false},
	}

	fs := afero.NewOsFs()
	for _, test := range tests {
		valid, _, err := ValidateByHash(fs, test.path, test.checksum)

		if err != nil && !test.err {
			t.Fatalf("failed to compute checksum: %+v", err)
		} else if err == nil && test.err {
			t.Fatalf("expected error but got none")
		}

		if valid != test.valid {
			t.Errorf("failed path='%s' valid='%t'", test.path, test.valid)
		}
	}
}
