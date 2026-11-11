package binary

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func Test_Cataloger_PythonMacOS(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		content     string
		symlinkFrom string // optional alias (relative to root) pointing at path
		wantVersion string
	}{
		{
			name:        "framework library",
			path:        "Python.framework/Versions/3.14/Python",
			content:     "junk\x003.14.10\x00junk",
			wantVersion: "3.14.10",
		},
		{
			name:        "framework library with Current alias",
			path:        "Python.framework/Versions/3.14/Python",
			content:     "junk\x003.14.10\x00junk",
			symlinkFrom: "Python.framework/Versions/Current/Python",
			wantVersion: "3.14.10",
		},
		{
			name:        "dylib",
			path:        "libpython3.14.dylib",
			content:     "junk\x003.14.6\x00junk",
			wantVersion: "3.14.6",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			full := filepath.Join(root, test.path)
			require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
			require.NoError(t, os.WriteFile(full, []byte(test.content), 0o644))
			if test.symlinkFrom != "" {
				alias := filepath.Join(root, test.symlinkFrom)
				require.NoError(t, os.MkdirAll(filepath.Dir(alias), 0o755))
				require.NoError(t, os.Symlink(full, alias))
			}

			src, err := directorysource.NewFromPath(root)
			require.NoError(t, err)
			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			c := NewClassifierCataloger(DefaultClassifierCatalogerConfig())
			pkgs, _, err := c.Catalog(context.Background(), resolver)
			require.NoError(t, err)
			require.Len(t, pkgs, 1)
			require.Equal(t, "python", pkgs[0].Name)
			require.Equal(t, test.wantVersion, pkgs[0].Version)
		})
	}
}
