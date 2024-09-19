package java

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
	maventest "github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven/test"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func Test_parsePomXML(t *testing.T) {
	tests := []struct {
		dir      string
		expected []pkg.Package
	}{
		{
			dir: "test-fixtures/pom/example-java-app-maven",
			expected: []pkg.Package{
				{
					Name:     "joda-time",
					Version:  "2.9.2",
					PURL:     "pkg:maven/com.joda/joda-time@2.9.2",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					FoundBy:  pomCatalogerName,
					Metadata: pkg.JavaArchive{
						PomProperties: &pkg.JavaPomProperties{
							GroupID:    "com.joda",
							ArtifactID: "joda-time",
						},
					},
				},
				{
					Name:     "junit",
					Version:  "4.12",
					PURL:     "pkg:maven/junit/junit@4.12",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					FoundBy:  pomCatalogerName,
					Metadata: pkg.JavaArchive{
						PomProperties: &pkg.JavaPomProperties{
							GroupID:    "junit",
							ArtifactID: "junit",
							Scope:      "test",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.dir, func(t *testing.T) {
			for i := range test.expected {
				test.expected[i].Locations.Add(file.NewLocation("pom.xml"))
			}

			cat := NewPomCataloger(ArchiveCatalogerConfig{
				ArchiveSearchConfig: cataloging.ArchiveSearchConfig{
					IncludeIndexedArchives:   true,
					IncludeUnindexedArchives: true,
				},
			})

			pkgtest.TestCataloger(t, test.dir, cat, test.expected, nil)
		})
	}
}

func Test_parseCommonsTextPomXMLProject(t *testing.T) {
	tests := []struct {
		dir      string
		expected []pkg.Package
	}{
		{
			dir: "test-fixtures/pom/commons-text-1.10.0",

			expected: getCommonsTextExpectedPackages(),
		},
	}

	for _, test := range tests {
		t.Run(test.dir, func(t *testing.T) {
			for i := range test.expected {
				test.expected[i].Locations.Add(file.NewLocation("pom.xml"))
			}

			cat := NewPomCataloger(ArchiveCatalogerConfig{
				ArchiveSearchConfig: cataloging.ArchiveSearchConfig{
					IncludeIndexedArchives:   true,
					IncludeUnindexedArchives: true,
				},
				UseMavenLocalRepository: false,
			})
			pkgtest.TestCataloger(t, test.dir, cat, test.expected, nil)
		})
	}
}

func Test_parseCommonsTextPomXMLProjectWithLocalRepository(t *testing.T) {
	mavenLocalRepoDir := "internal/maven/test-fixtures/maven-repo"

	// Using the local repository, the version of junit-jupiter will be resolved
	expectedPackages := getCommonsTextExpectedPackages()

	for i := 0; i < len(expectedPackages); i++ {
		if expectedPackages[i].Name == "junit-jupiter" {
			expPkg := &expectedPackages[i]
			expPkg.Version = "5.9.1"
			expPkg.PURL = "pkg:maven/org.junit.jupiter/junit-jupiter@5.9.1"
			expPkg.Metadata = pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.junit.jupiter",
					ArtifactID: "junit-jupiter",
					Scope:      "test",
				},
			}
		}
	}

	tests := []struct {
		dir      string
		expected []pkg.Package
	}{
		{
			dir:      "test-fixtures/pom/commons-text-1.10.0",
			expected: expectedPackages,
		},
	}

	for _, test := range tests {
		t.Run(test.dir, func(t *testing.T) {
			for i := range test.expected {
				test.expected[i].Locations.Add(file.NewLocation("pom.xml"))
			}

			cat := NewPomCataloger(ArchiveCatalogerConfig{
				ArchiveSearchConfig: cataloging.ArchiveSearchConfig{
					IncludeIndexedArchives:   true,
					IncludeUnindexedArchives: true,
				},
				UseMavenLocalRepository: true,
				MavenLocalRepositoryDir: mavenLocalRepoDir,
			})
			pkgtest.TestCataloger(t, test.dir, cat, test.expected, nil)
		})
	}
}

func Test_parseCommonsTextPomXMLProjectWithNetwork(t *testing.T) {
	url := maventest.MockRepo(t, "internal/maven/test-fixtures/maven-repo")

	// Using the local repository, the version of junit-jupiter will be resolved
	expectedPackages := getCommonsTextExpectedPackages()

	for i := 0; i < len(expectedPackages); i++ {
		if expectedPackages[i].Name == "junit-jupiter" {
			expPkg := &expectedPackages[i]
			expPkg.Version = "5.9.1"
			expPkg.PURL = "pkg:maven/org.junit.jupiter/junit-jupiter@5.9.1"
			expPkg.Metadata = pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.junit.jupiter",
					ArtifactID: "junit-jupiter",
					Scope:      "test",
				},
			}
		}
	}

	tests := []struct {
		dir      string
		expected []pkg.Package
	}{
		{
			dir:      "test-fixtures/pom/commons-text-1.10.0",
			expected: expectedPackages,
		},
	}

	for _, test := range tests {
		t.Run(test.dir, func(t *testing.T) {
			for i := range test.expected {
				test.expected[i].Locations.Add(file.NewLocation("pom.xml"))
			}

			cat := NewPomCataloger(ArchiveCatalogerConfig{
				ArchiveSearchConfig: cataloging.ArchiveSearchConfig{
					IncludeIndexedArchives:   true,
					IncludeUnindexedArchives: true,
				},
				UseNetwork:              true,
				MavenBaseURL:            url,
				UseMavenLocalRepository: false,
			})
			pkgtest.TestCataloger(t, test.dir, cat, test.expected, nil)
		})
	}
}

func Test_parsePomXMLProject(t *testing.T) {
	// TODO: ideally we would have the path to the contained pom.xml, not the jar
	jarLocation := file.NewLocation("path/to/archive.jar")
	tests := []struct {
		name     string
		project  *pkg.JavaPomProject
		licenses []pkg.License
	}{
		{
			name: "no license info",
			project: &pkg.JavaPomProject{
				Path: "test-fixtures/pom/commons-codec.pom.xml",
				Parent: &pkg.JavaPomParent{
					GroupID:    "org.apache.commons",
					ArtifactID: "commons-parent",
					Version:    "42",
				},
				GroupID:     "commons-codec",
				ArtifactID:  "commons-codec",
				Version:     "1.11",
				Name:        "Apache Commons Codec",
				Description: "The Apache Commons Codec package contains simple encoder and decoders for various formats such as Base64 and Hexadecimal.  In addition to these widely used encoders and decoders, the codec package also maintains a collection of phonetic encoding utilities.",
				URL:         "http://commons.apache.org/proper/commons-codec/",
			},
		},
		{
			name: "with license data",
			project: &pkg.JavaPomProject{
				Path: "test-fixtures/pom/neo4j-license-maven-plugin.pom.xml",
				Parent: &pkg.JavaPomParent{
					GroupID:    "org.sonatype.oss",
					ArtifactID: "oss-parent",
					Version:    "7",
				},
				GroupID:     "org.neo4j.build.plugins",
				ArtifactID:  "license-maven-plugin",
				Version:     "4-SNAPSHOT",
				Name:        "license-maven-plugin",
				Description: "Maven 2 plugin to check and update license headers in source files",
				URL:         "http://components.neo4j.org/license-maven-plugin/4-SNAPSHOT",
			},
			licenses: []pkg.License{
				{
					Value:          "The Apache Software License, Version 2.0",
					SPDXExpression: "", // TODO: ideally we would parse this title to get Apache-2.0 (created issue #2210 https://github.com/anchore/syft/issues/2210)
					Type:           license.Declared,
					URLs:           []string{"http://www.apache.org/licenses/LICENSE-2.0.txt"},
					Locations:      file.NewLocationSet(jarLocation),
				},
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           license.Declared,
					Locations:      file.NewLocationSet(jarLocation),
				},
				{
					Type:      license.Declared,
					URLs:      []string{"https://opensource.org/license/unlicense/"},
					Locations: file.NewLocationSet(jarLocation),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, err := os.Open(test.project.Path)
			assert.NoError(t, err)
			r := maven.NewResolver(nil, maven.Config{})

			pom, err := maven.ParsePomXML(fixture)
			require.NoError(t, err)

			actual := newPomProject(context.Background(), r, fixture.Name(), pom)
			assert.NoError(t, err)
			assert.Equal(t, test.project, actual)

			licenses, err := r.GetLicenses(context.Background(), pom)
			//assert.NoError(t, err)
			assert.Equal(t, test.licenses, toPkgLicenses(&jarLocation, licenses))
		})
	}
}

func Test_pomParent(t *testing.T) {
	tests := []struct {
		name     string
		input    *maven.Parent
		expected *pkg.JavaPomParent
	}{
		{
			name: "only group ID",
			input: &maven.Parent{
				GroupID: ptr("org.something"),
			},
			expected: &pkg.JavaPomParent{
				GroupID: "org.something",
			},
		},
		{
			name: "only artifact ID",
			input: &maven.Parent{
				ArtifactID: ptr("something"),
			},
			expected: &pkg.JavaPomParent{
				ArtifactID: "something",
			},
		},
		{
			name: "only Version",
			input: &maven.Parent{
				Version: ptr("something"),
			},
			expected: &pkg.JavaPomParent{
				Version: "something",
			},
		},
		{
			name:     "nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty",
			input:    &maven.Parent{},
			expected: nil,
		},
		{
			name: "unused field",
			input: &maven.Parent{
				RelativePath: ptr("something"),
			},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := maven.NewResolver(nil, maven.DefaultConfig())
			assert.Equal(t, test.expected, pomParent(context.Background(), r, &maven.Project{Parent: test.input}))
		})
	}
}

func Test_cleanDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "indent + multiline",
			input: `        The Apache Commons Codec package contains simple encoder and decoders for
        various formats such as Base64 and Hexadecimal.  In addition to these
        widely used encoders and decoders, the codec package also maintains a
        collection of phonetic encoding utilities.`,
			expected: "The Apache Commons Codec package contains simple encoder and decoders for various formats such as Base64 and Hexadecimal.  In addition to these widely used encoders and decoders, the codec package also maintains a collection of phonetic encoding utilities.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, cleanDescription(test.input))
		})
	}
}

func Test_resolveLicenses(t *testing.T) {
	mavenURL := maventest.MockRepo(t, "internal/maven/test-fixtures/maven-repo")
	localM2 := "internal/maven/test-fixtures/maven-repo"
	localDir := "internal/maven/test-fixtures/local"
	containingDir := "internal/maven/test-fixtures/local/contains-child-1"

	expectedLicenses := []pkg.License{
		{
			Value:          "Eclipse Public License v2.0",
			SPDXExpression: "",
			Type:           license.Declared,
			URLs:           []string{"https://www.eclipse.org/legal/epl-v20.html"},
		},
	}

	tests := []struct {
		name     string
		scanDir  string
		cfg      ArchiveCatalogerConfig
		expected []pkg.License
	}{
		{
			name:    "local no resolution",
			scanDir: containingDir,
			cfg: ArchiveCatalogerConfig{
				UseMavenLocalRepository: false,
				UseNetwork:              false,
				MavenLocalRepositoryDir: "",
				MavenBaseURL:            "",
			},
			expected: nil,
		},
		{
			name:    "local all poms",
			scanDir: localDir,
			cfg: ArchiveCatalogerConfig{
				UseMavenLocalRepository: false,
				UseNetwork:              false,
			},
			expected: expectedLicenses,
		},
		{
			name:    "local m2 cache",
			scanDir: containingDir,
			cfg: ArchiveCatalogerConfig{
				UseMavenLocalRepository: true,
				MavenLocalRepositoryDir: localM2,
				UseNetwork:              false,
				MavenBaseURL:            "",
			},
			expected: expectedLicenses,
		},
		{
			name:    "local with network",
			scanDir: containingDir,
			cfg: ArchiveCatalogerConfig{
				UseMavenLocalRepository: false,
				UseNetwork:              true,
				MavenBaseURL:            mavenURL,
			},
			expected: expectedLicenses,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cat := NewPomCataloger(test.cfg)

			ds, err := directorysource.NewFromPath(test.scanDir)
			require.NoError(t, err)

			fr, err := ds.FileResolver(source.AllLayersScope)
			require.NoError(t, err)

			ctx := context.TODO()
			pkgs, _, err := cat.Catalog(ctx, fr)
			require.NoError(t, err)

			var child1 pkg.Package
			for _, p := range pkgs {
				if p.Name == "child-one" {
					child1 = p
					break
				}
			}
			require.Equal(t, "child-one", child1.Name)

			got := child1.Licenses.ToSlice()
			for i := 0; i < len(got); i++ {
				// ignore locations, just check license text
				(&got[i]).Locations = file.LocationSet{}
			}
			require.ElementsMatch(t, test.expected, got)
		})
	}
}

func getCommonsTextExpectedPackages() []pkg.Package {
	return []pkg.Package{
		{
			Name:     "commons-lang3",
			Version:  "3.12.0",
			PURL:     "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.apache.commons",
					ArtifactID: "commons-lang3",
				},
			},
		},
		{
			Name:     "junit-jupiter",
			Version:  "",
			PURL:     "pkg:maven/org.junit.jupiter/junit-jupiter",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.junit.jupiter",
					ArtifactID: "junit-jupiter",
					Scope:      "test",
				},
			},
		},
		{
			Name:     "assertj-core",
			Version:  "3.23.1",
			PURL:     "pkg:maven/org.assertj/assertj-core@3.23.1",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.assertj",
					ArtifactID: "assertj-core",
					Scope:      "test",
				},
			},
		},
		{
			Name:     "commons-io",
			Version:  "2.11.0",
			PURL:     "pkg:maven/commons-io/commons-io@2.11.0",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "commons-io",
					ArtifactID: "commons-io",
					Scope:      "test",
				},
			},
		},
		{
			Name:     "mockito-inline",
			Version:  "4.8.0",
			PURL:     "pkg:maven/org.mockito/mockito-inline@4.8.0",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.mockito",
					ArtifactID: "mockito-inline",
					Scope:      "test",
				},
			},
		},
		{
			Name:     "js",
			Version:  "22.0.0.2",
			PURL:     "pkg:maven/org.graalvm.js/js@22.0.0.2",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.graalvm.js",
					ArtifactID: "js",
					Scope:      "test",
				},
			},
		},
		{
			Name:     "js-scriptengine",
			Version:  "22.0.0.2",
			PURL:     "pkg:maven/org.graalvm.js/js-scriptengine@22.0.0.2",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.graalvm.js",
					ArtifactID: "js-scriptengine",
					Scope:      "test",
				},
			},
		},
		{
			Name:     "commons-rng-simple",
			Version:  "1.4",
			PURL:     "pkg:maven/org.apache.commons/commons-rng-simple@1.4",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.apache.commons",
					ArtifactID: "commons-rng-simple",
					Scope:      "test",
				},
			},
		},
		{
			Name:     "jmh-core",
			Version:  "1.35",
			PURL:     "pkg:maven/org.openjdk.jmh/jmh-core@1.35",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.openjdk.jmh",
					ArtifactID: "jmh-core",
					Scope:      "test",
				},
			},
		},
		{
			Name:     "jmh-generator-annprocess",
			Version:  "1.35",
			PURL:     "pkg:maven/org.openjdk.jmh/jmh-generator-annprocess@1.35",
			Language: pkg.Java,
			Type:     pkg.JavaPkg,
			FoundBy:  pomCatalogerName,
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.openjdk.jmh",
					ArtifactID: "jmh-generator-annprocess",
					Scope:      "test",
				},
			},
		},
	}
}
