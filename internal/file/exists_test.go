package file

import (
	"github.com/spf13/afero"
	"testing"
)

func TestExists(t *testing.T) {
	var tests = []struct {
		path   string
		exists bool
	}{
		{"test-fixtures/generate-zip-fixture.sh", true},
		{"test-fixtures/non-existent-file", false},
	}

	fs := afero.NewOsFs()
	for _, test := range tests {
		if Exists(fs, test.path) != test.exists {
			t.Errorf("failed path='%s' exists='%t'", test.path, test.exists)
		}
	}
}
