package relationship

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func Test_excludeLanguagePackageByFileOwnershipOverlap(t *testing.T) {
	tests := []struct {
		name         string
		parent       *pkg.Package
		child        *pkg.Package
		shouldRemove bool
	}{
		{
			name: "OS package owns Python package - should remove Python package",
			parent: &pkg.Package{
				Name: "python3-django-deb",
				Type: pkg.DebPkg,
			},
			child: &pkg.Package{
				Name: "django",
				Type: pkg.PythonPkg,
			},
			shouldRemove: true,
		},
		{
			name: "Binary to Python - should not remove",
			parent: &pkg.Package{
				Name: "python-binary",
				Type: pkg.BinaryPkg,
			},
			child: &pkg.Package{
				Name: "django-py",
				Type: pkg.PythonPkg,
			},
			shouldRemove: false,
		},
		{
			name: "APK package owns Ruby package - should remove Ruby package",
			parent: &pkg.Package{
				Name: "ruby-rails-apk",
				Type: pkg.ApkPkg,
			},
			child: &pkg.Package{
				Name: "rails",
				Type: pkg.GemPkg,
			},
			shouldRemove: true,
		},
		{
			name: "RPM package owns NPM package - should remove NPM package",
			parent: &pkg.Package{
				Name: "nodejs-express-rpm",
				Type: pkg.RpmPkg,
			},
			child: &pkg.Package{
				Name: "express",
				Type: pkg.NpmPkg,
			},
			shouldRemove: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.parent.SetID()
			tt.child.SetID()

			collection := pkg.NewCollection()
			collection.Add(*tt.parent)
			collection.Add(*tt.child)

			rel := artifact.Relationship{
				From: *tt.parent,
				To:   *tt.child,
				Type: artifact.OwnershipByFileOverlapRelationship,
			}

			result := excludeLanguagePackageByFileOwnershipOverlap(rel, collection)

			if tt.shouldRemove {
				assert.Equal(t, tt.child.ID(), result, "should remove child package")
				assert.NotEqual(t, artifact.ID(""), result, "child ID must not be empty for a real assertion")
			} else {
				assert.Equal(t, artifact.ID(""), result, "should not remove any package")
			}
		})
	}
}

func Test_identifyOverlappingLanguageRelationship(t *testing.T) {
	tests := []struct {
		name         string
		parent       *pkg.Package
		child        *pkg.Package
		shouldRemove bool
	}{
		{
			name: "deb owns python - remove python",
			parent: &pkg.Package{
				Name: "python3-django-deb",
				Type: pkg.DebPkg,
			},
			child: &pkg.Package{
				Name: "django",
				Type: pkg.PythonPkg,
			},
			shouldRemove: true,
		},
		{
			name: "apk owns npm - remove npm",
			parent: &pkg.Package{
				Name: "nodejs-express-apk",
				Type: pkg.ApkPkg,
			},
			child: &pkg.Package{
				Name: "express",
				Type: pkg.NpmPkg,
			},
			shouldRemove: true,
		},
		{
			name: "rpm owns ruby - remove ruby",
			parent: &pkg.Package{
				Name: "ruby-rails-rpm",
				Type: pkg.RpmPkg,
			},
			child: &pkg.Package{
				Name: "rails",
				Type: pkg.GemPkg,
			},
			shouldRemove: true,
		},
		{
			// java-archive is binary-extracted (see binaryExtractedLanguageTypes): a JAR the deb owns may
			// contain nested components the deb does not subsume, so we must NOT delete it on overlap.
			name: "deb owns java archive - keep java (binary-extracted, not subsumed)",
			parent: &pkg.Package{
				Name: "libreoffice-java-common",
				Type: pkg.DebPkg,
			},
			child: &pkg.Package{
				Name: "some-jar",
				Type: pkg.JavaPkg,
			},
			shouldRemove: false,
		},
		{
			// go modules are extracted from a single OS-owned binary; deleting them would drop distinct
			// components (their identities/versions/licenses) the OS package does not replace.
			name: "deb owns go binary - keep go modules (binary-extracted, not subsumed)",
			parent: &pkg.Package{
				Name: "golang-github-foo-dev",
				Type: pkg.DebPkg,
			},
			child: &pkg.Package{
				Name: "github.com/foo/bar",
				Type: pkg.GoModulePkg,
			},
			shouldRemove: false,
		},
		{
			name: "binary owns python - keep both",
			parent: &pkg.Package{
				Name: "python-binary",
				Type: pkg.BinaryPkg,
			},
			child: &pkg.Package{
				Name: "django-py",
				Type: pkg.PythonPkg,
			},
			shouldRemove: false,
		},
		{
			name: "deb owns deb - keep both",
			parent: &pkg.Package{
				Name: "libfoo-deb",
				Type: pkg.DebPkg,
			},
			child: &pkg.Package{
				Name: "libbar-deb",
				Type: pkg.DebPkg,
			},
			shouldRemove: false,
		},
		{
			name: "python owns python - keep both",
			parent: &pkg.Package{
				Name: "django-parent",
				Type: pkg.PythonPkg,
			},
			child: &pkg.Package{
				Name: "django-child",
				Type: pkg.PythonPkg,
			},
			shouldRemove: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.parent.SetID()
			tt.child.SetID()

			result := identifyOverlappingLanguageRelationship(tt.parent, tt.child)

			if tt.shouldRemove {
				assert.Equal(t, tt.child.ID(), result, "should remove child package")
				assert.NotEqual(t, artifact.ID(""), result, "child ID must not be empty for a real assertion")
			} else {
				assert.Equal(t, artifact.ID(""), result, "should not remove any package")
			}
		})
	}
}
