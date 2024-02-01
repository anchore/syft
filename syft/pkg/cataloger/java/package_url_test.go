package java

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name   string
		pkg    pkg.Package
		expect string
	}{
		{
			name: "maven",
			pkg: pkg.Package{
				Name:     "example-java-app-maven",
				Version:  "0.1.0",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar",
					Manifest: &pkg.JavaManifest{
						Main: []pkg.KeyValue{
							{
								Key:   "Manifest-Version",
								Value: "1.0",
							},
						},
					},
					PomProperties: &pkg.JavaPomProperties{
						Path:       "META-INF/maven/org.anchore/example-java-app-maven/pom.properties",
						GroupID:    "org.anchore",
						ArtifactID: "example-java-app-maven",
						Version:    "0.1.0",
						Extra:      make(map[string]string),
					},
				},
			},
			expect: "pkg:maven/org.anchore/example-java-app-maven@0.1.0",
		},
		{
			name: "POM properties have explicit group ID without . in it",
			pkg: pkg.Package{
				Name:     "example-java-app-maven",
				Version:  "0.1.0",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar",
					Manifest: &pkg.JavaManifest{
						Main: []pkg.KeyValue{
							{
								Key:   "Manifest-Version",
								Value: "1.0",
							},
						},
					},
					PomProperties: &pkg.JavaPomProperties{
						Path:       "META-INF/maven/org.anchore/example-java-app-maven/pom.properties",
						GroupID:    "commons",
						ArtifactID: "example-java-app-maven",
						Version:    "0.1.0",
						Extra:      make(map[string]string),
					},
				},
			},
			expect: "pkg:maven/commons/example-java-app-maven@0.1.0",
		},
		{
			name: "POM project has explicit group ID without . in it",
			pkg: pkg.Package{
				Name:     "example-java-app-maven",
				Version:  "0.1.0",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar",
					Manifest: &pkg.JavaManifest{
						Main: []pkg.KeyValue{
							{
								Key:   "Manifest-Version",
								Value: "1.0",
							},
						},
					},
					PomProperties: &pkg.JavaPomProperties{
						Path:       "META-INF/maven/org.anchore/example-java-app-maven/pom.properties",
						ArtifactID: "example-java-app-maven",
						Version:    "0.1.0",
						Extra:      make(map[string]string),
					},
					PomProject: &pkg.JavaPomProject{
						GroupID: "commons",
					},
				},
			},
			expect: "pkg:maven/commons/example-java-app-maven@0.1.0",
		},
		{
			name: "POM project has explicit group ID without . in it",
			pkg: pkg.Package{
				Name:     "example-java-app-maven",
				Version:  "0.1.0",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar",
					Manifest: &pkg.JavaManifest{
						Main: []pkg.KeyValue{
							{
								Key:   "Manifest-Version",
								Value: "1.0",
							},
						},
					},
					PomProperties: &pkg.JavaPomProperties{
						Path:       "META-INF/maven/org.anchore/example-java-app-maven/pom.properties",
						ArtifactID: "example-java-app-maven",
						Version:    "0.1.0",
						Extra:      make(map[string]string),
					},
					PomProject: &pkg.JavaPomProject{
						Parent: &pkg.JavaPomParent{
							GroupID: "parent",
						},
					},
				},
			},
			expect: "pkg:maven/parent/example-java-app-maven@0.1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			assert.Equal(t, tt.expect, packageURL(tt.pkg.Name, tt.pkg.Version, tt.pkg.Metadata.(pkg.JavaArchive)))
		})
	}
}

func Test_groupIDFromJavaMetadata(t *testing.T) {
	tests := []struct {
		name     string
		pkgName  string
		metadata pkg.JavaArchive
		expect   string
	}{
		{
			name: "pom properties",
			metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID: "org.anchore",
				},
			},
			expect: "org.anchore",
		},
		{
			name: "pom project",
			metadata: pkg.JavaArchive{
				PomProject: &pkg.JavaPomProject{
					GroupID: "org.anchore",
				},
			},
			expect: "org.anchore",
		},
		{
			name:     "known package list",
			pkgName:  "ant-antlr",
			metadata: pkg.JavaArchive{},
			expect:   "org.apache.ant",
		},
		{
			name: "java manifest",
			metadata: pkg.JavaArchive{
				Manifest: &pkg.JavaManifest{
					Main: []pkg.KeyValue{
						{
							Key:   "Implementation-Vendor",
							Value: "org.anchore",
						},
					},
				},
			},
			expect: "org.anchore",
		},
		{
			name:     "no group id",
			metadata: pkg.JavaArchive{},
			expect:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, groupIDFromJavaMetadata(tt.pkgName, tt.metadata))
		})
	}
}
