package file

import (
	"io/ioutil"
	"testing"
)

func TestUnzip(t *testing.T) {
	var tests = []struct {
		path string
	}{
		{"test-fixtures/gzip-source/a-file.txt.gz"},
	}

	tempDir, _ := ioutil.TempDir("", "gzip_test")
	for _, test := range tests {
		err := UnGzip(tempDir, test.path)
		if err != nil {
			t.Errorf("failed to unzip %s", test.path)
		}
	}
}
