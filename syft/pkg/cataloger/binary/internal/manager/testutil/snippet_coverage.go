package testutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/internal/manager/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/internal/manager/internal/config"
)

// CheckFromURLsHaveSnippets verifies that every from-urls entry in config.yaml
// has a committed snippet for each of its targets.
//
// The check is intended to be called from the binary cataloger test package,
// where testdata is the current working directory's subdirectory.
func CheckFromURLsHaveSnippets(t *testing.T) {
	t.Helper()
	appConfig, entries := loadConfigAndEntries(t)
	checkFromURLs(t, appConfig, entries)
}

// CheckFromImagesHaveSnippets verifies that every from-images entry in config.yaml
// has a committed snippet for each of its targets.
//
// This is currently not enabled because existing from-images entries are not
// yet in a state where this check can pass.
func CheckFromImagesHaveSnippets(t *testing.T) {
	t.Helper()
	appConfig, entries := loadConfigAndEntries(t)
	checkFromImages(t, appConfig, entries)
}

func loadConfigAndEntries(t *testing.T) (*config.Application, internal.Entries) {
	t.Helper()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to get working directory: %v", err)
	}
	if err := os.Chdir("testdata"); err != nil {
		t.Fatalf("unable to chdir to testdata: %v", err)
	}
	defer func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("unable to restore working directory: %v", err)
		}
	}()

	appConfig, err := config.Read()
	if err != nil {
		t.Fatalf("unable to read config: %v", err)
	}

	entries, err := internal.ListAllEntries(*appConfig)
	if err != nil {
		t.Fatalf("unable to list entries: %v", err)
	}

	return appConfig, entries
}

func checkFromURLs(t *testing.T, appConfig *config.Application, entries internal.Entries) {
	t.Helper()

	for _, cfg := range appConfig.FromURLs {
		t.Run(cfg.Key(), func(t *testing.T) {
			assert.True(t, entries.BinaryFromURLHasSnippet(cfg),
				"from-urls entry %q is missing one or more snippets — cd to syft/pkg/cataloger/binary/testdata and run `make download` then `make add-snippet` to generate them",
				cfg.Key(),
			)
		})
	}
}

func checkFromImages(t *testing.T, appConfig *config.Application, entries internal.Entries) {
	t.Helper()

	for _, cfg := range appConfig.FromImages {
		t.Run(cfg.Key(), func(t *testing.T) {
			assert.True(t, entries.BinaryFromImageHasSnippet(cfg),
				"from-images entry %q is missing one or more snippets — cd to syft/pkg/cataloger/binary/testdata and run `make download` then `make add-snippet` to generate them",
				cfg.Key(),
			)
		})
	}
}
