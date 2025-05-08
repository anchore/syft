package task

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
)

func dummyTask(name string, tags ...string) Task {
	return NewTask(name, func(ctx context.Context, resolver file.Resolver, sbom sbomsync.Builder) error {
		panic("not implemented")
	}, tags...)
}

// note: this test fixture does not need to be kept up to date here, but makes a great test subject
func createDummyPackageTasks() tasks {
	return []Task{
		// OS package installed catalogers
		dummyTask("alpm-db-cataloger", "package", "directory", "installed", "image", "os", "alpm", "archlinux"),
		dummyTask("apk-db-cataloger", "package", "directory", "installed", "image", "os", "apk", "alpine"),
		dummyTask("dpkg-db-cataloger", "package", "directory", "installed", "image", "os", "dpkg", "debian"),
		dummyTask("portage-cataloger", "package", "directory", "installed", "image", "os", "portage", "gentoo"),
		dummyTask("rpm-db-cataloger", "package", "directory", "installed", "image", "os", "rpm", "redhat"),

		// OS package declared catalogers
		dummyTask("rpm-archive-cataloger", "package", "declared", "directory", "os", "rpm", "redhat"),

		// language-specific package installed catalogers
		dummyTask("conan-info-cataloger", "package", "installed", "image", "language", "cpp", "conan"),
		dummyTask("javascript-package-cataloger", "package", "installed", "image", "language", "javascript", "node"),
		dummyTask("php-composer-installed-cataloger", "package", "installed", "image", "language", "php", "composer"),
		dummyTask("ruby-installed-gemspec-cataloger", "package", "installed", "image", "language", "ruby", "gem", "gemspec"),
		dummyTask("rust-cargo-lock-cataloger", "package", "installed", "image", "language", "rust", "binary"),

		// language-specific package declared catalogers
		dummyTask("conan-cataloger", "package", "declared", "directory", "language", "cpp", "conan"),
		dummyTask("dart-pubspec-lock-cataloger", "package", "declared", "directory", "language", "dart"),
		dummyTask("dotnet-deps-cataloger", "package", "declared", "directory", "language", "dotnet", "c#"),
		dummyTask("elixir-mix-lock-cataloger", "package", "declared", "directory", "language", "elixir"),
		dummyTask("erlang-rebar-lock-cataloger", "package", "declared", "directory", "language", "erlang"),
		dummyTask("javascript-lock-cataloger", "package", "declared", "directory", "language", "javascript", "node", "npm"),

		// language-specific package for both image and directory scans (but not necessarily declared)
		dummyTask("dotnet-portable-executable-cataloger", "package", "directory", "installed", "image", "language", "dotnet", "c#"),
		dummyTask("python-installed-package-cataloger", "package", "directory", "installed", "image", "language", "python"),
		dummyTask("go-module-binary-cataloger", "package", "directory", "installed", "image", "language", "go", "golang", "gomod", "binary"),
		dummyTask("java-archive-cataloger", "package", "directory", "installed", "image", "language", "java", "maven"),
		dummyTask("graalvm-native-image-cataloger", "package", "directory", "installed", "image", "language", "java"),

		// other package catalogers
		dummyTask("binary-cataloger", "package", "declared", "directory", "image", "binary"),
		dummyTask("github-actions-usage-cataloger", "package", "declared", "directory", "github", "github-actions"),
		dummyTask("github-action-workflow-usage-cataloger", "package", "declared", "directory", "github", "github-actions"),
		dummyTask("sbom-cataloger", "package", "declared", "directory", "image", "sbom"),
	}
}

func createDummyFileTasks() tasks {
	return []Task{
		dummyTask("file-content-cataloger", "file", "content"),
		dummyTask("file-metadata-cataloger", "file", "metadata"),
		dummyTask("file-digest-cataloger", "file", "digest"),
		dummyTask("file-executable-cataloger", "file", "binary-metadata"),
	}
}

func TestSelect(t *testing.T) {

	tests := []struct {
		name        string
		allTasks    []Task
		basis       []string
		expressions []string
		wantNames   []string
		wantTokens  map[string]TokenSelection
		wantRequest cataloging.SelectionRequest
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			name:        "empty input",
			allTasks:    []Task{},
			basis:       []string{},
			expressions: []string{},
			wantNames:   []string{},
			wantTokens:  map[string]TokenSelection{},
			wantRequest: cataloging.SelectionRequest{},
		},
		{
			name:     "use default tasks",
			allTasks: createDummyPackageTasks(),
			basis: []string{
				"image",
			},
			expressions: []string{},
			wantNames: []string{
				"alpm-db-cataloger",
				"apk-db-cataloger",
				"dpkg-db-cataloger",
				"portage-cataloger",
				"rpm-db-cataloger",
				"conan-info-cataloger",
				"javascript-package-cataloger",
				"php-composer-installed-cataloger",
				"ruby-installed-gemspec-cataloger",
				"rust-cargo-lock-cataloger",
				"dotnet-portable-executable-cataloger",
				"python-installed-package-cataloger",
				"go-module-binary-cataloger",
				"java-archive-cataloger",
				"graalvm-native-image-cataloger",
				"binary-cataloger",
				"sbom-cataloger",
			},
			wantTokens: map[string]TokenSelection{
				"alpm-db-cataloger":                    newTokenSelection([]string{"image"}, nil),
				"apk-db-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"dpkg-db-cataloger":                    newTokenSelection([]string{"image"}, nil),
				"portage-cataloger":                    newTokenSelection([]string{"image"}, nil),
				"rpm-db-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"conan-info-cataloger":                 newTokenSelection([]string{"image"}, nil),
				"javascript-package-cataloger":         newTokenSelection([]string{"image"}, nil),
				"php-composer-installed-cataloger":     newTokenSelection([]string{"image"}, nil),
				"ruby-installed-gemspec-cataloger":     newTokenSelection([]string{"image"}, nil),
				"rust-cargo-lock-cataloger":            newTokenSelection([]string{"image"}, nil),
				"dotnet-portable-executable-cataloger": newTokenSelection([]string{"image"}, nil),
				"python-installed-package-cataloger":   newTokenSelection([]string{"image"}, nil),
				"go-module-binary-cataloger":           newTokenSelection([]string{"image"}, nil),
				"java-archive-cataloger":               newTokenSelection([]string{"image"}, nil),
				"graalvm-native-image-cataloger":       newTokenSelection([]string{"image"}, nil),
				"binary-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"sbom-cataloger":                       newTokenSelection([]string{"image"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"image"},
			},
		},
		{
			name:     "select, add, and remove tasks",
			allTasks: createDummyPackageTasks(),
			basis: []string{
				"image",
			},
			expressions: []string{
				"+github-actions-usage-cataloger",
				"-dpkg",
				"os",
			},
			wantNames: []string{
				"alpm-db-cataloger",
				"apk-db-cataloger",
				"portage-cataloger",
				"rpm-db-cataloger",
				"github-actions-usage-cataloger",
			},
			wantTokens: map[string]TokenSelection{
				// selected
				"alpm-db-cataloger":              newTokenSelection([]string{"image", "os"}, nil),
				"apk-db-cataloger":               newTokenSelection([]string{"image", "os"}, nil),
				"dpkg-db-cataloger":              newTokenSelection([]string{"image", "os"}, []string{"dpkg"}),
				"portage-cataloger":              newTokenSelection([]string{"image", "os"}, nil),
				"rpm-db-cataloger":               newTokenSelection([]string{"image", "os"}, nil),
				"github-actions-usage-cataloger": newTokenSelection([]string{"github-actions-usage-cataloger"}, nil),

				// ultimately not selected
				"rpm-archive-cataloger":                newTokenSelection([]string{"os"}, nil),
				"conan-info-cataloger":                 newTokenSelection([]string{"image"}, nil),
				"javascript-package-cataloger":         newTokenSelection([]string{"image"}, nil),
				"php-composer-installed-cataloger":     newTokenSelection([]string{"image"}, nil),
				"ruby-installed-gemspec-cataloger":     newTokenSelection([]string{"image"}, nil),
				"rust-cargo-lock-cataloger":            newTokenSelection([]string{"image"}, nil),
				"dotnet-portable-executable-cataloger": newTokenSelection([]string{"image"}, nil),
				"python-installed-package-cataloger":   newTokenSelection([]string{"image"}, nil),
				"go-module-binary-cataloger":           newTokenSelection([]string{"image"}, nil),
				"java-archive-cataloger":               newTokenSelection([]string{"image"}, nil),
				"graalvm-native-image-cataloger":       newTokenSelection([]string{"image"}, nil),
				"binary-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"sbom-cataloger":                       newTokenSelection([]string{"image"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"image"},
				SubSelectTags:      []string{"os"},
				RemoveNamesOrTags:  []string{"dpkg"},
				AddNames:           []string{"github-actions-usage-cataloger"},
			},
		},
		{
			name:     "allow for partial selections",
			allTasks: createDummyPackageTasks(),
			basis: []string{
				"image",
			},
			expressions: []string{
				// valid...
				"+github-actions-usage-cataloger",
				"-dpkg",
				"os",
				// invalid...
				"+python",
				"rust-cargo-lock-cataloger",
			},
			wantNames: []string{
				"alpm-db-cataloger",
				"apk-db-cataloger",
				"portage-cataloger",
				"rpm-db-cataloger",
				"github-actions-usage-cataloger",
			},
			wantTokens: map[string]TokenSelection{
				// selected
				"alpm-db-cataloger":              newTokenSelection([]string{"image", "os"}, nil),
				"apk-db-cataloger":               newTokenSelection([]string{"image", "os"}, nil),
				"dpkg-db-cataloger":              newTokenSelection([]string{"image", "os"}, []string{"dpkg"}),
				"portage-cataloger":              newTokenSelection([]string{"image", "os"}, nil),
				"rpm-db-cataloger":               newTokenSelection([]string{"image", "os"}, nil),
				"github-actions-usage-cataloger": newTokenSelection([]string{"github-actions-usage-cataloger"}, nil),

				// ultimately not selected
				"rpm-archive-cataloger":                newTokenSelection([]string{"os"}, nil),
				"conan-info-cataloger":                 newTokenSelection([]string{"image"}, nil),
				"javascript-package-cataloger":         newTokenSelection([]string{"image"}, nil),
				"php-composer-installed-cataloger":     newTokenSelection([]string{"image"}, nil),
				"ruby-installed-gemspec-cataloger":     newTokenSelection([]string{"image"}, nil),
				"rust-cargo-lock-cataloger":            newTokenSelection([]string{"image"}, nil),
				"dotnet-portable-executable-cataloger": newTokenSelection([]string{"image"}, nil),
				"python-installed-package-cataloger":   newTokenSelection([]string{"image"}, nil), // note: there is no python token used for selection
				"go-module-binary-cataloger":           newTokenSelection([]string{"image"}, nil),
				"java-archive-cataloger":               newTokenSelection([]string{"image"}, nil),
				"graalvm-native-image-cataloger":       newTokenSelection([]string{"image"}, nil),
				"binary-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"sbom-cataloger":                       newTokenSelection([]string{"image"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"image"},
				SubSelectTags:      []string{"os", "rust-cargo-lock-cataloger"},
				RemoveNamesOrTags:  []string{"dpkg"},
				AddNames:           []string{"github-actions-usage-cataloger", "python"},
			},
			wantErr: assert.Error, // !important!
		},
		{
			name:     "select all tasks",
			allTasks: createDummyPackageTasks(),
			basis: []string{
				"all",
			},
			expressions: []string{},
			wantNames: []string{
				"alpm-db-cataloger",
				"apk-db-cataloger",
				"dpkg-db-cataloger",
				"portage-cataloger",
				"rpm-db-cataloger",
				"rpm-archive-cataloger",
				"conan-info-cataloger",
				"javascript-package-cataloger",
				"php-composer-installed-cataloger",
				"ruby-installed-gemspec-cataloger",
				"rust-cargo-lock-cataloger",
				"conan-cataloger",
				"dart-pubspec-lock-cataloger",
				"dotnet-deps-cataloger",
				"elixir-mix-lock-cataloger",
				"erlang-rebar-lock-cataloger",
				"javascript-lock-cataloger",
				"dotnet-portable-executable-cataloger",
				"python-installed-package-cataloger",
				"go-module-binary-cataloger",
				"java-archive-cataloger",
				"graalvm-native-image-cataloger",
				"binary-cataloger",
				"github-actions-usage-cataloger",
				"github-action-workflow-usage-cataloger",
				"sbom-cataloger",
			},
			wantTokens: map[string]TokenSelection{
				"alpm-db-cataloger":                      newTokenSelection([]string{"all"}, nil),
				"apk-db-cataloger":                       newTokenSelection([]string{"all"}, nil),
				"dpkg-db-cataloger":                      newTokenSelection([]string{"all"}, nil),
				"portage-cataloger":                      newTokenSelection([]string{"all"}, nil),
				"rpm-db-cataloger":                       newTokenSelection([]string{"all"}, nil),
				"rpm-archive-cataloger":                  newTokenSelection([]string{"all"}, nil),
				"conan-info-cataloger":                   newTokenSelection([]string{"all"}, nil),
				"javascript-package-cataloger":           newTokenSelection([]string{"all"}, nil),
				"php-composer-installed-cataloger":       newTokenSelection([]string{"all"}, nil),
				"ruby-installed-gemspec-cataloger":       newTokenSelection([]string{"all"}, nil),
				"rust-cargo-lock-cataloger":              newTokenSelection([]string{"all"}, nil),
				"conan-cataloger":                        newTokenSelection([]string{"all"}, nil),
				"dart-pubspec-lock-cataloger":            newTokenSelection([]string{"all"}, nil),
				"dotnet-deps-cataloger":                  newTokenSelection([]string{"all"}, nil),
				"elixir-mix-lock-cataloger":              newTokenSelection([]string{"all"}, nil),
				"erlang-rebar-lock-cataloger":            newTokenSelection([]string{"all"}, nil),
				"javascript-lock-cataloger":              newTokenSelection([]string{"all"}, nil),
				"dotnet-portable-executable-cataloger":   newTokenSelection([]string{"all"}, nil),
				"python-installed-package-cataloger":     newTokenSelection([]string{"all"}, nil),
				"go-module-binary-cataloger":             newTokenSelection([]string{"all"}, nil),
				"java-archive-cataloger":                 newTokenSelection([]string{"all"}, nil),
				"graalvm-native-image-cataloger":         newTokenSelection([]string{"all"}, nil),
				"binary-cataloger":                       newTokenSelection([]string{"all"}, nil),
				"github-actions-usage-cataloger":         newTokenSelection([]string{"all"}, nil),
				"github-action-workflow-usage-cataloger": newTokenSelection([]string{"all"}, nil),
				"sbom-cataloger":                         newTokenSelection([]string{"all"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"all"},
			},
		},
		{
			name:     "set default with multiple tags",
			allTasks: createDummyPackageTasks(),
			basis: []string{
				"gemspec",
				"python",
			},
			expressions: []string{},
			wantNames: []string{
				"ruby-installed-gemspec-cataloger",
				"python-installed-package-cataloger",
			},
			wantTokens: map[string]TokenSelection{
				"ruby-installed-gemspec-cataloger":   newTokenSelection([]string{"gemspec"}, nil),
				"python-installed-package-cataloger": newTokenSelection([]string{"python"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"gemspec", "python"},
			},
		},
		{
			name:        "automatically add file to default tags",
			allTasks:    createDummyFileTasks(),
			basis:       []string{},
			expressions: []string{},
			wantNames: []string{
				"file-content-cataloger",
				"file-metadata-cataloger",
				"file-digest-cataloger",
				"file-executable-cataloger",
			},
			wantTokens: map[string]TokenSelection{
				"file-content-cataloger":    newTokenSelection([]string{"file"}, nil),
				"file-metadata-cataloger":   newTokenSelection([]string{"file"}, nil),
				"file-digest-cataloger":     newTokenSelection([]string{"file"}, nil),
				"file-executable-cataloger": newTokenSelection([]string{"file"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"file"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}

			req := cataloging.NewSelectionRequest().WithDefaults(tt.basis...).WithExpression(tt.expressions...)

			got, gotEvidence, err := Select(tt.allTasks, req)
			tt.wantErr(t, err)
			if err != nil {
				// dev note: this is useful for debugging when needed...
				//for _, e := range gotEvidence.Request.Expressions {
				//	t.Logf("expression (errors %q): %#v", e.Errors, e)
				//}

				// note: we DON'T bail early in validations... this is because we should always return the full set of
				// of selected tasks and surrounding evidence.
			}

			gotNames := make([]string, 0)
			for _, g := range got {
				gotNames = append(gotNames, g.Name())
			}

			assert.Equal(t, tt.wantNames, gotNames)

			// names in selection should match all tasks returned
			require.Len(t, tt.wantNames, gotEvidence.Result.Size(), "selected tasks should match all tasks returned (but does not)")
			assert.ElementsMatch(t, tt.wantNames, gotEvidence.Result.List(), "selected tasks should match all tasks returned (but does not)")

			setCompare := cmp.Comparer(func(x, y *strset.Set) bool {
				return x.IsEqual(y)
			})

			if d := cmp.Diff(tt.wantTokens, gotEvidence.TokensByTask, setCompare); d != "" {
				t.Errorf("unexpected tokens by task (-want +got):\n%s", d)
			}
			assert.Equal(t, tt.wantRequest, gotEvidence.Request)

		})
	}
}

func TestSelectInGroups(t *testing.T) {
	tests := []struct {
		name         string
		taskGroups   [][]Task
		selectionReq cataloging.SelectionRequest
		wantGroups   [][]string
		wantTokens   map[string]TokenSelection
		wantRequest  cataloging.SelectionRequest
		wantErr      assert.ErrorAssertionFunc
	}{
		{
			name: "select only within the file tasks (leave package tasks alone)",
			taskGroups: [][]Task{
				createDummyPackageTasks(),
				createDummyFileTasks(),
			},
			selectionReq: cataloging.NewSelectionRequest().
				WithDefaults("image"). // note: file missing
				WithSubSelections("content", "digest"),
			wantGroups: [][]string{
				{
					// this is the original, untouched package task list
					"alpm-db-cataloger",
					"apk-db-cataloger",
					"dpkg-db-cataloger",
					"portage-cataloger",
					"rpm-db-cataloger",
					"conan-info-cataloger",
					"javascript-package-cataloger",
					"php-composer-installed-cataloger",
					"ruby-installed-gemspec-cataloger",
					"rust-cargo-lock-cataloger",
					"dotnet-portable-executable-cataloger",
					"python-installed-package-cataloger",
					"go-module-binary-cataloger",
					"java-archive-cataloger",
					"graalvm-native-image-cataloger",
					"binary-cataloger",
					"sbom-cataloger",
				},
				{
					// this has been filtered based on the request
					"file-content-cataloger",
					"file-digest-cataloger",
				},
			},
			wantTokens: map[string]TokenSelection{
				// packages
				"alpm-db-cataloger":                    newTokenSelection([]string{"image"}, nil),
				"apk-db-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"binary-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"conan-info-cataloger":                 newTokenSelection([]string{"image"}, nil),
				"dotnet-portable-executable-cataloger": newTokenSelection([]string{"image"}, nil),
				"dpkg-db-cataloger":                    newTokenSelection([]string{"image"}, nil),
				"go-module-binary-cataloger":           newTokenSelection([]string{"image"}, nil),
				"graalvm-native-image-cataloger":       newTokenSelection([]string{"image"}, nil),
				"java-archive-cataloger":               newTokenSelection([]string{"image"}, nil),
				"javascript-package-cataloger":         newTokenSelection([]string{"image"}, nil),
				"php-composer-installed-cataloger":     newTokenSelection([]string{"image"}, nil),
				"portage-cataloger":                    newTokenSelection([]string{"image"}, nil),
				"python-installed-package-cataloger":   newTokenSelection([]string{"image"}, nil),
				"rpm-db-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"ruby-installed-gemspec-cataloger":     newTokenSelection([]string{"image"}, nil),
				"rust-cargo-lock-cataloger":            newTokenSelection([]string{"image"}, nil),
				"sbom-cataloger":                       newTokenSelection([]string{"image"}, nil),
				// files
				"file-content-cataloger":    newTokenSelection([]string{"content", "file"}, nil),
				"file-digest-cataloger":     newTokenSelection([]string{"digest", "file"}, nil),
				"file-executable-cataloger": newTokenSelection([]string{"file"}, nil),
				"file-metadata-cataloger":   newTokenSelection([]string{"file"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"image", "file"}, // note: file automatically added
				SubSelectTags:      []string{"content", "digest"},
			},
			wantErr: assert.NoError,
		},
		{
			name: "select package tasks (leave file tasks alone)",
			taskGroups: [][]Task{
				createDummyPackageTasks(),
				createDummyFileTasks(),
			},
			selectionReq: cataloging.NewSelectionRequest().WithDefaults("image").WithSubSelections("os"),
			wantGroups: [][]string{
				{
					// filtered based on the request
					"alpm-db-cataloger",
					"apk-db-cataloger",
					"dpkg-db-cataloger",
					"portage-cataloger",
					"rpm-db-cataloger",
				},
				{
					// this is the original, untouched file task list
					"file-content-cataloger",
					"file-metadata-cataloger",
					"file-digest-cataloger",
					"file-executable-cataloger",
				},
			},
			wantTokens: map[string]TokenSelection{
				// packages - os
				"alpm-db-cataloger":     newTokenSelection([]string{"os", "image"}, nil),
				"apk-db-cataloger":      newTokenSelection([]string{"os", "image"}, nil),
				"rpm-archive-cataloger": newTokenSelection([]string{"os"}, nil),
				"rpm-db-cataloger":      newTokenSelection([]string{"os", "image"}, nil),
				"portage-cataloger":     newTokenSelection([]string{"os", "image"}, nil),
				"dpkg-db-cataloger":     newTokenSelection([]string{"os", "image"}, nil),
				// packages - remaining
				"binary-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"conan-info-cataloger":                 newTokenSelection([]string{"image"}, nil),
				"dotnet-portable-executable-cataloger": newTokenSelection([]string{"image"}, nil),
				"go-module-binary-cataloger":           newTokenSelection([]string{"image"}, nil),
				"graalvm-native-image-cataloger":       newTokenSelection([]string{"image"}, nil),
				"java-archive-cataloger":               newTokenSelection([]string{"image"}, nil),
				"javascript-package-cataloger":         newTokenSelection([]string{"image"}, nil),
				"php-composer-installed-cataloger":     newTokenSelection([]string{"image"}, nil),
				"python-installed-package-cataloger":   newTokenSelection([]string{"image"}, nil),
				"ruby-installed-gemspec-cataloger":     newTokenSelection([]string{"image"}, nil),
				"rust-cargo-lock-cataloger":            newTokenSelection([]string{"image"}, nil),
				"sbom-cataloger":                       newTokenSelection([]string{"image"}, nil),
				// files
				"file-content-cataloger":    newTokenSelection([]string{"file"}, nil),
				"file-digest-cataloger":     newTokenSelection([]string{"file"}, nil),
				"file-executable-cataloger": newTokenSelection([]string{"file"}, nil),
				"file-metadata-cataloger":   newTokenSelection([]string{"file"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"image", "file"},
				SubSelectTags:      []string{"os"},
			},
			wantErr: assert.NoError,
		},
		{
			name: "select only file tasks (default)",
			taskGroups: [][]Task{
				createDummyPackageTasks(),
				createDummyFileTasks(),
			},
			selectionReq: cataloging.NewSelectionRequest().WithDefaults("file"),
			wantGroups: [][]string{
				// filtered based on the request
				nil,
				{
					// this is the original, untouched file task list
					"file-content-cataloger",
					"file-metadata-cataloger",
					"file-digest-cataloger",
					"file-executable-cataloger",
				},
			},
			wantTokens: map[string]TokenSelection{
				// files
				"file-content-cataloger":    newTokenSelection([]string{"file"}, nil),
				"file-digest-cataloger":     newTokenSelection([]string{"file"}, nil),
				"file-executable-cataloger": newTokenSelection([]string{"file"}, nil),
				"file-metadata-cataloger":   newTokenSelection([]string{"file"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"file"},
			},
			wantErr: assert.NoError,
		},
		{
			name: "select only file tasks (via removal of package)",
			taskGroups: [][]Task{
				createDummyPackageTasks(),
				createDummyFileTasks(),
			},
			selectionReq: cataloging.NewSelectionRequest().WithDefaults("file", "image").WithRemovals("package"),
			wantGroups: [][]string{
				// filtered based on the request
				nil,
				{
					// this is the original, untouched file task list
					"file-content-cataloger",
					"file-metadata-cataloger",
					"file-digest-cataloger",
					"file-executable-cataloger",
				},
			},
			wantTokens: map[string]TokenSelection{
				// packages
				"alpm-db-cataloger":                      newTokenSelection([]string{"image"}, []string{"package"}),
				"apk-db-cataloger":                       newTokenSelection([]string{"image"}, []string{"package"}),
				"binary-cataloger":                       newTokenSelection([]string{"image"}, []string{"package"}),
				"conan-info-cataloger":                   newTokenSelection([]string{"image"}, []string{"package"}),
				"dotnet-portable-executable-cataloger":   newTokenSelection([]string{"image"}, []string{"package"}),
				"dpkg-db-cataloger":                      newTokenSelection([]string{"image"}, []string{"package"}),
				"go-module-binary-cataloger":             newTokenSelection([]string{"image"}, []string{"package"}),
				"graalvm-native-image-cataloger":         newTokenSelection([]string{"image"}, []string{"package"}),
				"java-archive-cataloger":                 newTokenSelection([]string{"image"}, []string{"package"}),
				"javascript-package-cataloger":           newTokenSelection([]string{"image"}, []string{"package"}),
				"php-composer-installed-cataloger":       newTokenSelection([]string{"image"}, []string{"package"}),
				"portage-cataloger":                      newTokenSelection([]string{"image"}, []string{"package"}),
				"python-installed-package-cataloger":     newTokenSelection([]string{"image"}, []string{"package"}),
				"rpm-db-cataloger":                       newTokenSelection([]string{"image"}, []string{"package"}),
				"ruby-installed-gemspec-cataloger":       newTokenSelection([]string{"image"}, []string{"package"}),
				"rust-cargo-lock-cataloger":              newTokenSelection([]string{"image"}, []string{"package"}),
				"sbom-cataloger":                         newTokenSelection([]string{"image"}, []string{"package"}),
				"rpm-archive-cataloger":                  newTokenSelection(nil, []string{"package"}),
				"conan-cataloger":                        newTokenSelection(nil, []string{"package"}),
				"dart-pubspec-lock-cataloger":            newTokenSelection(nil, []string{"package"}),
				"dotnet-deps-cataloger":                  newTokenSelection(nil, []string{"package"}),
				"elixir-mix-lock-cataloger":              newTokenSelection(nil, []string{"package"}),
				"erlang-rebar-lock-cataloger":            newTokenSelection(nil, []string{"package"}),
				"javascript-lock-cataloger":              newTokenSelection(nil, []string{"package"}),
				"github-actions-usage-cataloger":         newTokenSelection(nil, []string{"package"}),
				"github-action-workflow-usage-cataloger": newTokenSelection(nil, []string{"package"}),
				// files
				"file-content-cataloger":    newTokenSelection([]string{"file"}, nil),
				"file-digest-cataloger":     newTokenSelection([]string{"file"}, nil),
				"file-executable-cataloger": newTokenSelection([]string{"file"}, nil),
				"file-metadata-cataloger":   newTokenSelection([]string{"file"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"file", "image"},
				RemoveNamesOrTags:  []string{"package"},
			},
			wantErr: assert.NoError,
		},
		{
			name: "select file and package tasks",
			taskGroups: [][]Task{
				createDummyPackageTasks(),
				createDummyFileTasks(),
			},
			selectionReq: cataloging.NewSelectionRequest().
				WithDefaults("image").
				WithSubSelections("os", "content", "digest"),
			wantGroups: [][]string{
				{
					// filtered based on the request
					"alpm-db-cataloger",
					"apk-db-cataloger",
					"dpkg-db-cataloger",
					"portage-cataloger",
					"rpm-db-cataloger",
				},
				{
					// filtered based on the request
					"file-content-cataloger",
					"file-digest-cataloger",
				},
			},
			wantTokens: map[string]TokenSelection{
				// packages - os
				"alpm-db-cataloger":     newTokenSelection([]string{"os", "image"}, nil),
				"apk-db-cataloger":      newTokenSelection([]string{"os", "image"}, nil),
				"rpm-archive-cataloger": newTokenSelection([]string{"os"}, nil),
				"rpm-db-cataloger":      newTokenSelection([]string{"os", "image"}, nil),
				"portage-cataloger":     newTokenSelection([]string{"os", "image"}, nil),
				"dpkg-db-cataloger":     newTokenSelection([]string{"os", "image"}, nil),
				// packages - remaining
				"binary-cataloger":                     newTokenSelection([]string{"image"}, nil),
				"conan-info-cataloger":                 newTokenSelection([]string{"image"}, nil),
				"dotnet-portable-executable-cataloger": newTokenSelection([]string{"image"}, nil),
				"go-module-binary-cataloger":           newTokenSelection([]string{"image"}, nil),
				"graalvm-native-image-cataloger":       newTokenSelection([]string{"image"}, nil),
				"java-archive-cataloger":               newTokenSelection([]string{"image"}, nil),
				"javascript-package-cataloger":         newTokenSelection([]string{"image"}, nil),
				"php-composer-installed-cataloger":     newTokenSelection([]string{"image"}, nil),
				"python-installed-package-cataloger":   newTokenSelection([]string{"image"}, nil),
				"ruby-installed-gemspec-cataloger":     newTokenSelection([]string{"image"}, nil),
				"rust-cargo-lock-cataloger":            newTokenSelection([]string{"image"}, nil),
				"sbom-cataloger":                       newTokenSelection([]string{"image"}, nil),
				// files
				"file-content-cataloger":    newTokenSelection([]string{"file", "content"}, nil), // note extra tags
				"file-digest-cataloger":     newTokenSelection([]string{"file", "digest"}, nil),  // note extra tags
				"file-executable-cataloger": newTokenSelection([]string{"file"}, nil),
				"file-metadata-cataloger":   newTokenSelection([]string{"file"}, nil),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"image", "file"},
				SubSelectTags:      []string{"os", "content", "digest"},
			},
			wantErr: assert.NoError,
		},
		{
			name: "complex selection with multiple operators across groups",
			taskGroups: [][]Task{
				createDummyPackageTasks(),
				createDummyFileTasks(),
			},
			selectionReq: cataloging.NewSelectionRequest().
				WithDefaults("os"). // note: no file tag present
				WithExpression("+github-actions-usage-cataloger", "-dpkg", "-digest", "content", "+file-metadata-cataloger", "-declared"),
			wantGroups: [][]string{
				{
					"alpm-db-cataloger",
					"apk-db-cataloger",
					"portage-cataloger",
					"rpm-db-cataloger",
					"github-actions-usage-cataloger",
				},
				{
					"file-content-cataloger",
					"file-metadata-cataloger",
				},
			},
			wantTokens: map[string]TokenSelection{
				// selected package tasks
				"alpm-db-cataloger":              newTokenSelection([]string{"os"}, nil),
				"apk-db-cataloger":               newTokenSelection([]string{"os"}, nil),
				"dpkg-db-cataloger":              newTokenSelection([]string{"os"}, []string{"dpkg"}),
				"portage-cataloger":              newTokenSelection([]string{"os"}, nil),
				"rpm-archive-cataloger":          newTokenSelection([]string{"os"}, []string{"declared"}),
				"rpm-db-cataloger":               newTokenSelection([]string{"os"}, nil),
				"github-actions-usage-cataloger": newTokenSelection([]string{"github-actions-usage-cataloger"}, []string{"declared"}),

				// selected file tasks
				"file-content-cataloger":  newTokenSelection([]string{"content", "file"}, nil),
				"file-metadata-cataloger": newTokenSelection([]string{"file-metadata-cataloger", "file"}, nil),

				// removed package tasks
				"binary-cataloger":                       newTokenSelection(nil, []string{"declared"}),
				"conan-cataloger":                        newTokenSelection(nil, []string{"declared"}),
				"dart-pubspec-lock-cataloger":            newTokenSelection(nil, []string{"declared"}),
				"dotnet-deps-cataloger":                  newTokenSelection(nil, []string{"declared"}),
				"elixir-mix-lock-cataloger":              newTokenSelection(nil, []string{"declared"}),
				"erlang-rebar-lock-cataloger":            newTokenSelection(nil, []string{"declared"}),
				"github-action-workflow-usage-cataloger": newTokenSelection(nil, []string{"declared"}),
				"javascript-lock-cataloger":              newTokenSelection(nil, []string{"declared"}),
				"sbom-cataloger":                         newTokenSelection(nil, []string{"declared"}),

				// removed file tasks
				"file-executable-cataloger": newTokenSelection([]string{"file"}, nil),
				"file-digest-cataloger":     newTokenSelection([]string{"file"}, []string{"digest"}),
			},
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"os", "file"}, // note: file added automatically
				SubSelectTags:      []string{"content"},
				RemoveNamesOrTags:  []string{"dpkg", "digest", "declared"},
				AddNames:           []string{"github-actions-usage-cataloger", "file-metadata-cataloger"},
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid tag",
			taskGroups: [][]Task{
				createDummyPackageTasks(),
				createDummyFileTasks(),
			},
			selectionReq: cataloging.NewSelectionRequest().WithDefaults("invalid"),
			wantGroups:   nil,
			wantTokens:   nil,
			wantRequest: cataloging.SelectionRequest{
				DefaultNamesOrTags: []string{"invalid", "file"},
			},
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}

			gotGroups, gotSelection, err := SelectInGroups(tt.taskGroups, tt.selectionReq)
			tt.wantErr(t, err)
			if err != nil {
				// dev note: this is useful for debugging when needed...
				//for _, e := range gotEvidence.Request.Expressions {
				//	t.Logf("expression (errors %q): %#v", e.Errors, e)
				//}

				// note: we DON'T bail early in validations... this is because we should always return the full set of
				// of selected tasks and surrounding evidence.
			}

			var gotGroupNames [][]string
			for _, group := range gotGroups {
				var names []string
				for _, task := range group {
					names = append(names, task.Name())
				}
				gotGroupNames = append(gotGroupNames, names)
			}

			assert.Equal(t, tt.wantGroups, gotGroupNames)
			assert.Equal(t, tt.wantTokens, gotSelection.TokensByTask)
			assert.Equal(t, tt.wantRequest, gotSelection.Request)
		})
	}
}
