package golang

import (
	"os"
	"testing"
)

func TestparseGoBin(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "parseGoBin identifies a go binary and returns a package",
			path: "/Users/hal/go/bin/syft",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			file, err := os.Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}

			_, err = parseGoBin(tt.path, file)
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}
