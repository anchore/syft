package relationship

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func Test_excludeLanguagePackageByFileOwnershipOverlap(t *testing.T) {
	tests := []struct {
		name         string
		relationship artifact.Relationship
		parent       *pkg.Package
		child        *pkg.Package
		expected     artifact.ID
	}{
		{
			name: "OS package owns Python package - should remove Python package",
			relationship: artifact.Relationship{
				From: pkg.Package{
					Type: pkg.DebPkg,
				},
				To: pkg.Package{
					Type: pkg.PythonPkg,
				},
				Type: artifact.OwnershipByFileOverlapRelationship,
			},
			parent: &pkg.Package{
				Type: pkg.DebPkg,
			},
			child: &pkg.Package{
				Type: pkg.PythonPkg,
			},
			expected: "", // will be child.ID() in actual implementation
		},
		{
			name: "Binary to Python - should not remove",
			relationship: artifact.Relationship{
				From: pkg.Package{
					Type: pkg.BinaryPkg,
				},
				To: pkg.Package{
					Type: pkg.PythonPkg,
				},
				Type: artifact.OwnershipByFileOverlapRelationship,
			},
			parent: &pkg.Package{
				Type: pkg.BinaryPkg,
			},
			child: &pkg.Package{
				Type: pkg.PythonPkg,
			},
			expected: "",
		},
		{
			name: "APK package owns Ruby package - should remove Ruby package",
			relationship: artifact.Relationship{
				From: pkg.Package{
					Type: pkg.ApkPkg,
				},
				To: pkg.Package{
					Type: pkg.GemPkg,
				},
				Type: artifact.OwnershipByFileOverlapRelationship,
			},
			parent: &pkg.Package{
				Type: pkg.ApkPkg,
			},
			child: &pkg.Package{
				Type: pkg.GemPkg,
			},
			expected: "", // will be child.ID() in actual implementation
		},
		{
			name: "RPM package owns NPM package - should remove NPM package",
			relationship: artifact.Relationship{
				From: pkg.Package{
					Type: pkg.RpmPkg,
				},
				To: pkg.Package{
					Type: pkg.NpmPkg,
				},
				Type: artifact.OwnershipByFileOverlapRelationship,
			},
			parent: &pkg.Package{
				Type: pkg.RpmPkg,
			},
			child: &pkg.Package{
				Type: pkg.NpmPkg,
			},
			expected: "", // will be child.ID() in actual implementation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collection := pkg.NewCollection()
			collection.Add(*tt.parent)
			collection.Add(*tt.child)

			tt.relationship.From = *tt.parent
			tt.relationship.To = *tt.child

			result := excludeLanguagePackageByFileOwnershipOverlap(tt.relationship, collection)

			// For OS -> language package, we should get the child ID
			if slices.Contains(osCatalogerTypes, tt.parent.Type) && slices.Contains(languageCatalogerTypes, tt.child.Type) {
				assert.Equal(t, tt.child.ID(), result)
			} else {
				assert.Equal(t, artifact.ID(""), result)
			}
		})
	}
}

func Test_identifyOverlappingLanguageRelationship(t *testing.T) {
	tests := []struct {
		name           string
		parent         *pkg.Package
		child          *pkg.Package
		shouldRemove   bool
		expectedToKeep string
	}{
		{
			name: "deb owns python - remove python",
			parent: &pkg.Package{
				Type: pkg.DebPkg,
			},
			child: &pkg.Package{
				Type: pkg.PythonPkg,
			},
			shouldRemove: true,
		},
		{
			name: "apk owns npm - remove npm",
			parent: &pkg.Package{
				Type: pkg.ApkPkg,
			},
			child: &pkg.Package{
				Type: pkg.NpmPkg,
			},
			shouldRemove: true,
		},
		{
			name: "rpm owns ruby - remove ruby",
			parent: &pkg.Package{
				Type: pkg.RpmPkg,
			},
			child: &pkg.Package{
				Type: pkg.GemPkg,
			},
			shouldRemove: true,
		},
		{
			name: "binary owns python - keep both",
			parent: &pkg.Package{
				Type: pkg.BinaryPkg,
			},
			child: &pkg.Package{
				Type: pkg.PythonPkg,
			},
			shouldRemove: false,
		},
		{
			name: "deb owns deb - keep both",
			parent: &pkg.Package{
				Type: pkg.DebPkg,
			},
			child: &pkg.Package{
				Type: pkg.DebPkg,
			},
			shouldRemove: false,
		},
		{
			name: "python owns python - keep both",
			parent: &pkg.Package{
				Type: pkg.PythonPkg,
			},
			child: &pkg.Package{
				Type: pkg.PythonPkg,
			},
			shouldRemove: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := identifyOverlappingLanguageRelationship(tt.parent, tt.child)

			if tt.shouldRemove {
				assert.Equal(t, tt.child.ID(), result, "should remove child package")
			} else {
				assert.Equal(t, artifact.ID(""), result, "should not remove any package")
			}
		})
	}
}
