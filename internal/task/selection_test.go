package task

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
)

func dummyTask(name string, tags ...string) Task {
	return NewTask(name, func(resolver file.Resolver, sbom sbomsync.Builder) error {
		panic("not implemented")
	}, tags...)
}

// note: this test fixture does not need to be kept up to date here, but makes a great test subject
func createDummyTasks() tasks {
	return []Task{
		// OS package installed catalogers
		dummyTask("alpm-db-cataloger", "directory", "installed", "image", "os", "alpm", "archlinux"),
		dummyTask("apk-db-cataloger", "directory", "installed", "image", "os", "apk", "alpine"),
		dummyTask("dpkg-db-cataloger", "directory", "installed", "image", "os", "dpkg", "debian"),
		dummyTask("portage-cataloger", "directory", "installed", "image", "os", "portage", "gentoo"),
		dummyTask("rpm-db-cataloger", "directory", "installed", "image", "os", "rpm", "redhat"),

		// OS package declared catalogers
		dummyTask("rpm-archive-cataloger", "declared", "directory", "os", "rpm", "redhat"),

		// language-specific package installed catalogers
		dummyTask("conan-info-cataloger", "installed", "image", "language", "cpp", "conan"),
		dummyTask("javascript-package-cataloger", "installed", "image", "language", "javascript", "node"),
		dummyTask("php-composer-installed-cataloger", "installed", "image", "language", "php", "composer"),
		dummyTask("ruby-installed-gemspec-cataloger", "installed", "image", "language", "ruby", "gem"),
		dummyTask("rust-cargo-lock-cataloger", "installed", "image", "language", "rust", "binary"),

		// language-specific package declared catalogers
		dummyTask("conan-cataloger", "declared", "directory", "language", "cpp", "conan"),
		dummyTask("dart-pubspec-lock-cataloger", "declared", "directory", "language", "dart"),
		dummyTask("dotnet-deps-cataloger", "declared", "directory", "language", "dotnet", "c#"),
		dummyTask("elixir-mix-lock-cataloger", "declared", "directory", "language", "elixir"),
		dummyTask("erlang-rebar-lock-cataloger", "declared", "directory", "language", "erlang"),
		dummyTask("javascript-lock-cataloger", "declared", "directory", "language", "javascript", "node", "npm"),

		// language-specific package for both image and directory scans (but not necessarily declared)
		dummyTask("dotnet-portable-executable-cataloger", "directory", "installed", "image", "language", "dotnet", "c#"),
		dummyTask("python-installed-package-cataloger", "directory", "installed", "image", "language", "python"),
		dummyTask("go-module-binary-cataloger", "directory", "installed", "image", "language", "go", "golang", "gomod", "binary"),
		dummyTask("java-archive-cataloger", "directory", "installed", "image", "language", "java", "maven"),
		dummyTask("graalvm-native-image-cataloger", "directory", "installed", "image", "language", "java"),

		// other package catalogers
		dummyTask("binary-cataloger", "declared", "directory", "image", "binary"),
		dummyTask("github-actions-usage-cataloger", "declared", "directory", "github", "github-actions"),
		dummyTask("github-action-workflow-usage-cataloger", "declared", "directory", "github", "github-actions"),
		dummyTask("sbom-cataloger", "declared", "directory", "image", "sbom"),
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
		wantRequest SelectionRequest
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			name:        "empty input",
			allTasks:    []Task{},
			basis:       []string{},
			expressions: []string{},
			wantNames:   []string{},
			wantTokens:  map[string]TokenSelection{},
			wantRequest: SelectionRequest{
				Default:   []string{},
				Selection: []string{},
			},
		},
		{
			name:     "use default tasks",
			allTasks: createDummyTasks(),
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
			wantRequest: SelectionRequest{
				Expressions: []Expression{
					{
						Operation: SetOperation,
						Operand:   "image",
						Errors:    nil,
					},
				},
				Default:   []string{"image"},
				Selection: []string{},
			},
		},
		{
			name:     "select, add, and remove tasks",
			allTasks: createDummyTasks(),
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
			wantRequest: SelectionRequest{
				Expressions: []Expression{
					{
						Operation: SetOperation,
						Operand:   "image",
						Errors:    nil,
					},
					{
						Operation: SubSelectOperation,
						Operand:   "os",
						Errors:    nil,
					},
					{
						Operation: RemoveOperation,
						Operand:   "dpkg",
						Errors:    nil,
					},
					{
						Operation: AddOperation,
						Operand:   "github-actions-usage-cataloger",
						Errors:    nil,
					},
				},
				Default: []string{"image"},
				Selection: []string{
					"os",
					"-dpkg",
					"+github-actions-usage-cataloger",
				},
			},
		},
		{
			name:     "allow for partial selections",
			allTasks: createDummyTasks(),
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
			wantRequest: SelectionRequest{
				// note: this is an ordered expression (based on operation primarily)
				Expressions: []Expression{
					{
						Operation: SetOperation,
						Operand:   "image",
						Errors:    nil,
					},
					{
						Operation: SubSelectOperation,
						Operand:   "os",
						Errors:    nil,
					},
					{
						Operation: SubSelectOperation,
						Operand:   "rust-cargo-lock-cataloger",
						Errors:    []error{newErrInvalidExpression("rust-cargo-lock-cataloger", SubSelectOperation, ErrNamesNotAllowed)},
					},
					{
						Operation: RemoveOperation,
						Operand:   "dpkg",
						Errors:    nil,
					},
					{
						Operation: AddOperation,
						Operand:   "github-actions-usage-cataloger",
						Errors:    nil,
					},
					{
						Operation: AddOperation,
						Operand:   "python",
						Errors:    []error{newErrInvalidExpression("+python", AddOperation, ErrTagsNotAllowed)},
					},
				},
				Default: []string{"image"},
				Selection: []string{
					// note: nodes that have errors are not included in the selection
					"os",
					"-dpkg",
					"+github-actions-usage-cataloger",
				},
			},
			wantErr: assert.Error, // !important!
		},
		{
			name:     "select all tasks",
			allTasks: createDummyTasks(),
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
			wantRequest: SelectionRequest{
				Expressions: []Expression{
					{
						Operation: SetOperation,
						Operand:   "all",
						Errors:    nil,
					},
				},
				Default:   []string{"all"},
				Selection: []string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			got, gotEvidence, err := Select(tt.allTasks, tt.basis, tt.expressions)
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
