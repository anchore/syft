package java

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gookit/color"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
	maventest "github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven/test"
)

func TestSearchMavenForLicenses(t *testing.T) {
	url := maventest.MockRepo(t, "internal/maven/test-fixtures/maven-repo")

	ctx := licenses.SetContextLicenseScanner(context.Background(), licenses.TestingOnlyScanner())

	tests := []struct {
		name             string
		fixture          string
		detectNested     bool
		config           ArchiveCatalogerConfig
		expectedLicenses []pkg.License
	}{
		{
			name:         "searchMavenForLicenses returns the expected licenses when search is set to true",
			fixture:      "opensaml-core-3.4.6",
			detectNested: false,
			config: ArchiveCatalogerConfig{
				UseNetwork:              true,
				UseMavenLocalRepository: false,
				MavenBaseURL:            url,
			},
			expectedLicenses: []pkg.License{
				{
					Type:  license.Declared,
					Value: `The Apache Software License, Version 2.0`,
					URLs: []string{
						"http://www.apache.org/licenses/LICENSE-2.0.txt",
					},
					SPDXExpression: ``,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// setup metadata fixture; note:
			// this fixture has a pomProjectObject and has a parent object
			// it has no licenses on either which is the condition for testing
			// the searchMavenForLicenses functionality
			jarName := generateJavaMetadataJarFixture(t, tc.fixture, "jar")
			fixture, err := os.Open(jarName)
			require.NoError(t, err)

			// setup parser
			ap, cleanupFn, err := newJavaArchiveParser(
				ctx,
				file.LocationReadCloser{
					Location:   file.NewLocation(fixture.Name()),
					ReadCloser: fixture,
				}, tc.detectNested, tc.config)
			defer cleanupFn()

			// assert licenses are discovered from upstream
			_, _, _, parsedPom := ap.discoverMainPackageFromPomInfo(context.Background())
			resolvedLicenses, _ := ap.maven.ResolveLicenses(context.Background(), parsedPom.project)
			assert.Equal(t, tc.expectedLicenses, toPkgLicenses(nil, resolvedLicenses))
		})
	}
}

func TestParseJar(t *testing.T) {
	ctx := licenses.SetContextLicenseScanner(context.Background(), licenses.TestingOnlyScanner())

	tests := []struct {
		name         string
		fixture      string
		expected     map[string]pkg.Package
		ignoreExtras []string
		wantErr      require.ErrorAssertionFunc
	}{
		{
			name:    "example-jenkins-plugin",
			fixture: "test-fixtures/java-builds/packages/example-jenkins-plugin.hpi",
			wantErr: require.Error, // there are nested jars, which are not scanned and result in unknown errors
			ignoreExtras: []string{
				"Plugin-Version", // has dynamic date
				"Built-By",       // podman returns the real UID
				"Build-Jdk",      // can't guarantee the JDK used at build time
			},
			expected: map[string]pkg.Package{
				"example-jenkins-plugin": {
					Name:    "example-jenkins-plugin",
					Version: "1.0-SNAPSHOT",
					PURL:    "pkg:maven/io.jenkins.plugins/example-jenkins-plugin@1.0-SNAPSHOT",
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocations("MIT License", file.NewLocation("test-fixtures/java-builds/packages/example-jenkins-plugin.hpi")),
					),
					Language: pkg.Java,
					Type:     pkg.JenkinsPluginPkg,
					Metadata: pkg.JavaArchive{
						VirtualPath: "test-fixtures/java-builds/packages/example-jenkins-plugin.hpi",
						Manifest: &pkg.JavaManifest{
							Main: pkg.KeyValues{
								{Key: "Manifest-Version", Value: "1.0"},
								{Key: "Created-By", Value: "Maven Archiver 3.6.0"},
								{Key: "Build-Jdk-Spec", Value: "18"},
								{Key: "Specification-Title", Value: "Example Jenkins Plugin"},
								{Key: "Specification-Version", Value: "1.0"},
								{Key: "Implementation-Title", Value: "Example Jenkins Plugin"},
								{Key: "Implementation-Version", Value: "1.0-SNAPSHOT"},
								{Key: "Group-Id", Value: "io.jenkins.plugins"},
								{Key: "Short-Name", Value: "example-jenkins-plugin"},
								{Key: "Long-Name", Value: "Example Jenkins Plugin"},
								{Key: "Hudson-Version", Value: "2.204"},
								{Key: "Jenkins-Version", Value: "2.204"},
								{Key: "Plugin-Dependencies", Value: "structs:1.20"},
								{Key: "Plugin-Developers", Value: ""},
								{Key: "Plugin-License-Name", Value: "MIT License"},
								{Key: "Plugin-License-Url", Value: "https://opensource.org/licenses/MIT"},
								{Key: "Plugin-ScmUrl", Value: "https://github.com/jenkinsci/plugin-pom/example-jenkins-plugin"},
								// extra fields...
								//{Key: "Minimum-Java-Version", Value: "1.8"},
								//{Key: "Archiver-Version", Value: "Plexus Archiver"},
								//{Key: "Built-By", Value: "?"},
								//{Key: "Build-Jdk", Value: "14.0.1"},
								//{Key: "Extension-Name", Value: "example-jenkins-plugin"},
								//{Key: "Plugin-Version", Value: "1.0-SNAPSHOT (private-07/09/2020 13:30-?)"},
							},
						},
						PomProperties: &pkg.JavaPomProperties{
							Path:       "META-INF/maven/io.jenkins.plugins/example-jenkins-plugin/pom.properties",
							GroupID:    "io.jenkins.plugins",
							ArtifactID: "example-jenkins-plugin",
							Version:    "1.0-SNAPSHOT",
						},
					},
				},
			},
		},
		{
			name:    "example-java-app-gradle",
			fixture: "test-fixtures/java-builds/packages/example-java-app-gradle-0.1.0.jar",
			wantErr: require.NoError, // no nested jars
			expected: map[string]pkg.Package{
				"example-java-app-gradle": {
					Name:     "example-java-app-gradle",
					Version:  "0.1.0",
					PURL:     "pkg:maven/example-java-app-gradle/example-java-app-gradle@0.1.0",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.License{
							Value:          "Apache-2.0",
							SPDXExpression: "Apache-2.0",
							Type:           license.Concluded,
							Locations:      file.NewLocationSet(file.NewLocation("test-fixtures/java-builds/packages/example-java-app-gradle-0.1.0.jar")),
						},
					),
					Metadata: pkg.JavaArchive{
						VirtualPath: "test-fixtures/java-builds/packages/example-java-app-gradle-0.1.0.jar",
						Manifest: &pkg.JavaManifest{
							Main: []pkg.KeyValue{
								{
									Key:   "Manifest-Version",
									Value: "1.0",
								},
								{
									Key:   "Main-Class",
									Value: "hello.HelloWorld",
								},
							},
						},
					},
				},
				"joda-time": {
					Name:     "joda-time",
					Version:  "2.2",
					PURL:     "pkg:maven/joda-time/joda-time@2.2",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromFields(
							"Apache 2",
							"http://www.apache.org/licenses/LICENSE-2.0.txt",
							func() *file.Location {
								l := file.NewLocation("test-fixtures/java-builds/packages/example-java-app-gradle-0.1.0.jar")
								return &l
							}(),
						),
					),
					Metadata: pkg.JavaArchive{
						// ensure that nested packages with different names than that of the parent are appended as
						// a suffix on the virtual path with a colon separator between group name and artifact name
						VirtualPath: "test-fixtures/java-builds/packages/example-java-app-gradle-0.1.0.jar:joda-time:joda-time",
						PomProperties: &pkg.JavaPomProperties{
							Path:       "META-INF/maven/joda-time/joda-time/pom.properties",
							GroupID:    "joda-time",
							ArtifactID: "joda-time",
							Version:    "2.2",
						},
						PomProject: &pkg.JavaPomProject{
							Path:        "META-INF/maven/joda-time/joda-time/pom.xml",
							GroupID:     "joda-time",
							ArtifactID:  "joda-time",
							Version:     "2.2",
							Name:        "Joda time",
							Description: "Date and time library to replace JDK date handling",
							URL:         "http://joda-time.sourceforge.net",
						},
					},
				},
			},
		},
		{
			name:    "example-java-app-maven",
			fixture: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar",
			wantErr: require.NoError, // no nested jars
			ignoreExtras: []string{
				"Build-Jdk", // can't guarantee the JDK used at build time
				"Built-By",  // podman returns the real UID
			},
			expected: map[string]pkg.Package{
				"example-java-app-maven": {
					Name:     "example-java-app-maven",
					Version:  "0.1.0",
					PURL:     "pkg:maven/org.anchore/example-java-app-maven@0.1.0",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.License{
							Value:          "Apache-2.0",
							SPDXExpression: "Apache-2.0",
							Type:           license.Concluded,
							Locations:      file.NewLocationSet(file.NewLocation("test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar")),
						},
					),
					Metadata: pkg.JavaArchive{
						VirtualPath: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar",
						Manifest: &pkg.JavaManifest{
							Main: []pkg.KeyValue{
								{
									Key:   "Manifest-Version",
									Value: "1.0",
								},
								// extra fields...
								{
									Key:   "Archiver-Version",
									Value: "Plexus Archiver",
								},
								{
									Key:   "Created-By",
									Value: "Apache Maven 3.8.6",
								},
								//{
								//  Key:   "Built-By",
								//  Value: "?",
								//},
								//{
								//	Key:   "Build-Jdk",
								//	Value: "14.0.1",
								//},
								{
									Key:   "Main-Class",
									Value: "hello.HelloWorld",
								},
							},
						},
						PomProperties: &pkg.JavaPomProperties{
							Path:       "META-INF/maven/org.anchore/example-java-app-maven/pom.properties",
							GroupID:    "org.anchore",
							ArtifactID: "example-java-app-maven",
							Version:    "0.1.0",
						},
					},
				},
				"joda-time": {
					Name:    "joda-time",
					Version: "2.9.2",
					PURL:    "pkg:maven/joda-time/joda-time@2.9.2",
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromFields(
							"Apache 2",
							"http://www.apache.org/licenses/LICENSE-2.0.txt",
							func() *file.Location {
								l := file.NewLocation("test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar")
								return &l
							}(),
						),
					),
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					Metadata: pkg.JavaArchive{
						// ensure that nested packages with different names than that of the parent are appended as
						// a suffix on the virtual path
						VirtualPath: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar:joda-time:joda-time",
						PomProperties: &pkg.JavaPomProperties{
							Path:       "META-INF/maven/joda-time/joda-time/pom.properties",
							GroupID:    "joda-time",
							ArtifactID: "joda-time",
							Version:    "2.9.2",
						},
						PomProject: &pkg.JavaPomProject{
							Path:        "META-INF/maven/joda-time/joda-time/pom.xml",
							GroupID:     "joda-time",
							ArtifactID:  "joda-time",
							Version:     "2.9.2",
							Name:        "Joda-Time",
							Description: "Date and time library to replace JDK date handling",
							URL:         "http://www.joda.org/joda-time/",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			generateJavaBuildFixture(t, test.fixture)

			fixture, err := os.Open(test.fixture)
			require.NoError(t, err)

			for k := range test.expected {
				p := test.expected[k]
				p.Locations.Add(file.NewLocation(test.fixture))
				test.expected[k] = p
			}

			cfg := ArchiveCatalogerConfig{
				UseNetwork:              false,
				UseMavenLocalRepository: false,
			}
			parser, cleanupFn, err := newJavaArchiveParser(
				ctx,
				file.LocationReadCloser{
					Location:   file.NewLocation(fixture.Name()),
					ReadCloser: fixture,
				}, false, cfg)
			defer cleanupFn()
			require.NoError(t, err)

			actual, _, err := parser.parse(context.Background(), nil)
			if test.wantErr != nil {
				test.wantErr(t, err)
			} else {
				require.NoError(t, err)
			}

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count; expected: %d got: %d", len(test.expected), len(actual))
			}

			var parent *pkg.Package
			for _, a := range actual {
				a := a
				if strings.Contains(a.Name, "example-") {
					parent = &a
				}
			}

			if parent == nil {
				t.Fatal("could not find the parent pkg")
			}

			for _, a := range actual {
				if a.ID() == "" {
					t.Fatalf("empty package ID: %+v", a)
				}

				e, ok := test.expected[a.Name]
				if !ok {
					t.Errorf("entry not found: %s", a.Name)
					continue
				}

				if a.Name != parent.Name && a.Metadata.(pkg.JavaArchive).Parent != nil && a.Metadata.(pkg.JavaArchive).Parent.Name != parent.Name {
					t.Errorf("mismatched parent: %+v", a.Metadata.(pkg.JavaArchive).Parent)
				}

				// we need to compare the other fields without parent attached
				metadata := a.Metadata.(pkg.JavaArchive)
				metadata.Parent = nil

				// redact Digest which is computed differently between CI and local
				if len(metadata.ArchiveDigests) > 0 {
					metadata.ArchiveDigests = nil
				}

				// ignore select fields (only works for the main section)
				for _, field := range test.ignoreExtras {
					if metadata.Manifest != nil && metadata.Manifest.Main != nil {
						newMain := make(pkg.KeyValues, 0)
						for i, kv := range metadata.Manifest.Main {
							if kv.Key == field {
								continue
							}
							newMain = append(newMain, metadata.Manifest.Main[i])
						}
						metadata.Manifest.Main = newMain
					}
				}

				// write censored data back
				a.Metadata = metadata

				pkgtest.AssertPackagesEqual(t, e, a)
			}
		})
	}
}

func TestParseNestedJar(t *testing.T) {
	tests := []struct {
		fixture      string
		expected     []pkg.Package
		ignoreExtras []string
	}{
		{
			fixture: "test-fixtures/java-builds/packages/spring-boot-0.0.1-SNAPSHOT.jar",
			expected: []pkg.Package{
				{
					Name:    "spring-boot",
					Version: "0.0.1-SNAPSHOT",
				},
				{
					Name:    "spring-boot-starter",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "jul-to-slf4j",
					Version: "1.7.29",
				},
				{
					Name:    "tomcat-embed-websocket",
					Version: "9.0.29",
				},
				{
					Name:    "spring-boot-starter-validation",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "hibernate-validator",
					Version: "6.0.18.Final",
				},
				{
					Name:    "jboss-logging",
					Version: "3.4.1.Final",
				},
				{
					Name:    "spring-expression",
					Version: "5.2.2.RELEASE",
				},
				{
					Name:    "jakarta.validation-api",
					Version: "2.0.1",
				},
				{
					Name:    "spring-web",
					Version: "5.2.2.RELEASE",
				},
				{
					Name:    "spring-boot-starter-actuator",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "log4j-api",
					Version: "2.12.1",
				},
				{
					Name:    "snakeyaml",
					Version: "1.25",
				},
				{
					Name:    "jackson-core",
					Version: "2.10.1",
				},
				{
					Name:    "jackson-datatype-jsr310",
					Version: "2.10.1",
				},
				{
					Name:    "spring-aop",
					Version: "5.2.2.RELEASE",
				},
				{
					Name:    "spring-boot-actuator-autoconfigure",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "spring-jcl",
					Version: "5.2.2.RELEASE",
				},
				{
					Name:    "spring-boot",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "spring-boot-starter-logging",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "jakarta.annotation-api",
					Version: "1.3.5",
				},
				{
					Name:    "spring-webmvc",
					Version: "5.2.2.RELEASE",
				},
				{
					Name:    "HdrHistogram",
					Version: "2.1.11",
				},
				{
					Name:    "spring-boot-starter-web",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "logback-classic",
					Version: "1.2.3",
				},
				{
					Name:    "log4j-to-slf4j",
					Version: "2.12.1",
				},
				{
					Name:    "spring-boot-starter-json",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "jackson-databind",
					Version: "2.10.1",
				},
				{
					Name:    "jackson-module-parameter-names",
					Version: "2.10.1",
				},
				{
					Name:    "LatencyUtils",
					Version: "2.0.3",
				},
				{
					Name:    "spring-boot-autoconfigure",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "jackson-datatype-jdk8",
					Version: "2.10.1",
				},
				{
					Name:    "tomcat-embed-core",
					Version: "9.0.29",
				},
				{
					Name:    "tomcat-embed-el",
					Version: "9.0.29",
				},
				{
					Name:    "spring-beans",
					Version: "5.2.2.RELEASE",
				},
				{
					Name:    "spring-boot-actuator",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "slf4j-api",
					Version: "1.7.29",
				},
				{
					Name:    "spring-core",
					Version: "5.2.2.RELEASE",
				},
				{
					Name:    "logback-core",
					Version: "1.2.3",
				},
				{
					Name:    "micrometer-core",
					Version: "1.3.1",
				},
				{
					Name:    "pcollections",
					Version: "3.1.0",
				},
				{
					Name:    "jackson-annotations",
					Version: "2.10.1",
				},
				{
					Name:    "spring-boot-starter-tomcat",
					Version: "2.2.2.RELEASE",
				},
				{
					Name:    "classmate",
					Version: "1.5.1",
				},
				{
					Name:    "spring-context",
					Version: "5.2.2.RELEASE",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {

			generateJavaBuildFixture(t, test.fixture)

			fixture, err := os.Open(test.fixture)
			require.NoError(t, err)
			gap := newGenericArchiveParserAdapter(ArchiveCatalogerConfig{})

			actual, _, err := gap.processJavaArchive(context.Background(), file.LocationReadCloser{
				Location:   file.NewLocation(fixture.Name()),
				ReadCloser: fixture,
			}, nil)
			require.NoError(t, err)

			expectedNameVersionPairSet := strset.New()

			makeKey := func(p *pkg.Package) string {
				if p == nil {
					t.Fatal("cannot make key for nil pkg")
				}
				return fmt.Sprintf("%s|%s", p.Name, p.Version)
			}

			for _, e := range test.expected {
				expectedNameVersionPairSet.Add(makeKey(&e))
			}

			actualNameVersionPairSet := strset.New()
			for _, a := range actual {
				a := a
				key := makeKey(&a)
				actualNameVersionPairSet.Add(key)
				if !expectedNameVersionPairSet.Has(key) {
					t.Errorf("extra package: %s", a)
				}
			}

			for _, key := range expectedNameVersionPairSet.List() {
				if !actualNameVersionPairSet.Has(key) {
					t.Errorf("missing package: %s", key)
				}
			}

			if len(actual) != expectedNameVersionPairSet.Size() {
				t.Fatalf("unexpected package count: %d!=%d", len(actual), expectedNameVersionPairSet.Size())
			}

			for _, a := range actual {
				a := a
				actualKey := makeKey(&a)

				metadata := a.Metadata.(pkg.JavaArchive)
				if actualKey == "spring-boot|0.0.1-SNAPSHOT" {
					if metadata.Parent != nil {
						t.Errorf("expected no parent for root pkg, got %q", makeKey(metadata.Parent))
					}
				} else {
					if metadata.Parent == nil {
						t.Errorf("unassigned error for pkg=%q", actualKey)
					} else if makeKey(metadata.Parent) != "spring-boot|0.0.1-SNAPSHOT" {
						// NB: this is a hard-coded condition to simplify the test harness to account for https://github.com/micrometer-metrics/micrometer/issues/1785
						if a.Name == "pcollections" {
							if metadata.Parent.Name != "micrometer-core" {
								t.Errorf("nested 'pcollections' pkg has wrong parent: %q", metadata.Parent.Name)
							}
						} else {
							t.Errorf("bad parent for pkg=%q parent=%q", actualKey, makeKey(metadata.Parent))
						}
					}
				}
			}
		})
	}
}

func Test_newPackageFromMavenData(t *testing.T) {
	virtualPath := "given/virtual/path"
	tests := []struct {
		name            string
		props           pkg.JavaPomProperties
		project         *parsedPomProject
		parent          *pkg.Package
		expectedParent  pkg.Package
		expectedPackage *pkg.Package
	}{
		{
			name: "go case: get a single package from pom properties",
			props: pkg.JavaPomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-artifact-id",
				Version:    "1.0",
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaArchive{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			// note: the SAME as the original parent values
			expectedParent: pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaArchive{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			expectedPackage: &pkg.Package{
				Name:     "some-artifact-id",
				Version:  "1.0",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: virtualPath + ":" + "some-group-id" + ":" + "some-artifact-id",
					PomProperties: &pkg.JavaPomProperties{
						Name:       "some-name",
						GroupID:    "some-group-id",
						ArtifactID: "some-artifact-id",
						Version:    "1.0",
					},
					Parent: &pkg.Package{
						Name:    "some-parent-name",
						Version: "2.0",
						Metadata: pkg.JavaArchive{
							VirtualPath:   "some-parent-virtual-path",
							Manifest:      nil,
							PomProperties: nil,
							Parent:        nil,
						},
					},
				},
			},
		},
		{
			name: "get a single package from pom properties + project",
			props: pkg.JavaPomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-artifact-id",
				Version:    "1.0",
			},
			project: &parsedPomProject{
				project: &maven.Project{
					Parent: &maven.Parent{
						GroupID:    ptr("some-parent-group-id"),
						ArtifactID: ptr("some-parent-artifact-id"),
						Version:    ptr("1.0-parent"),
					},
					Name:        ptr("some-name"),
					GroupID:     ptr("some-group-id"),
					ArtifactID:  ptr("some-artifact-id"),
					Version:     ptr("1.0"),
					Description: ptr("desc"),
					URL:         ptr("aweso.me"),
					Licenses: &[]maven.License{
						{
							Name: ptr("MIT"),
							URL:  ptr("https://opensource.org/licenses/MIT"),
						},
					},
				},
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaArchive{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			// note: the SAME as the original parent values
			expectedParent: pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaArchive{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			expectedPackage: &pkg.Package{
				Name:     "some-artifact-id",
				Version:  "1.0",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.License{
						Value:          "MIT",
						SPDXExpression: "MIT",
						Type:           license.Declared,
						URLs:           []string{"https://opensource.org/licenses/MIT"},
						Locations:      file.NewLocationSet(file.NewLocation("given/virtual/path")),
					},
				),
				Metadata: pkg.JavaArchive{
					VirtualPath: virtualPath + ":" + "some-group-id" + ":" + "some-artifact-id",
					PomProperties: &pkg.JavaPomProperties{
						Name:       "some-name",
						GroupID:    "some-group-id",
						ArtifactID: "some-artifact-id",
						Version:    "1.0",
					},
					PomProject: &pkg.JavaPomProject{
						Parent: &pkg.JavaPomParent{
							GroupID:    "some-parent-group-id",
							ArtifactID: "some-parent-artifact-id",
							Version:    "1.0-parent",
						},
						Name:        "some-name",
						GroupID:     "some-group-id",
						ArtifactID:  "some-artifact-id",
						Version:     "1.0",
						Description: "desc",
						URL:         "aweso.me",
					},
					Parent: &pkg.Package{
						Name:    "some-parent-name",
						Version: "2.0",
						Metadata: pkg.JavaArchive{
							VirtualPath:   "some-parent-virtual-path",
							Manifest:      nil,
							PomProperties: nil,
							Parent:        nil,
						},
					},
				},
			},
		},
		{
			name: "single package from pom properties that's a Jenkins plugin",
			props: pkg.JavaPomProperties{
				Name:       "some-name",
				GroupID:    "com.cloudbees.jenkins.plugins",
				ArtifactID: "some-artifact-id",
				Version:    "1.0",
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaArchive{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			// note: the SAME as the original parent values
			expectedParent: pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaArchive{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			expectedPackage: &pkg.Package{
				Name:     "some-artifact-id",
				Version:  "1.0",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: virtualPath + ":" + "com.cloudbees.jenkins.plugins" + ":" + "some-artifact-id",
					PomProperties: &pkg.JavaPomProperties{
						Name:       "some-name",
						GroupID:    "com.cloudbees.jenkins.plugins",
						ArtifactID: "some-artifact-id",
						Version:    "1.0",
					},
					Parent: &pkg.Package{
						Name:    "some-parent-name",
						Version: "2.0",
						Metadata: pkg.JavaArchive{
							VirtualPath:   "some-parent-virtual-path",
							Manifest:      nil,
							PomProperties: nil,
							Parent:        nil,
						},
					},
				},
			},
		},
		{
			name: "child matches parent by key",
			props: pkg.JavaPomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-parent-name", // note: matches parent package
				Version:    "2.0",              // note: matches parent package
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			// note: the SAME as the original parent values
			expectedParent: pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: "some-parent-virtual-path",
					Manifest:    nil,
					// note: we attach the discovered pom properties data
					PomProperties: &pkg.JavaPomProperties{
						Name:       "some-name",
						GroupID:    "some-group-id",
						ArtifactID: "some-parent-name", // note: matches parent package
						Version:    "2.0",              // note: matches parent package
					},
					Parent: nil,
				},
			},
			expectedPackage: nil,
		},
		{
			name: "child matches parent by key and is Jenkins plugin",
			props: pkg.JavaPomProperties{
				Name:       "some-name",
				GroupID:    "com.cloudbees.jenkins.plugins",
				ArtifactID: "some-parent-name", // note: matches parent package
				Version:    "2.0",              // note: matches parent package
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			expectedParent: pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Type:    pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: "some-parent-virtual-path",
					Manifest:    nil,
					// note: we attach the discovered pom properties data
					PomProperties: &pkg.JavaPomProperties{
						Name:       "some-name",
						GroupID:    "com.cloudbees.jenkins.plugins",
						ArtifactID: "some-parent-name", // note: matches parent package
						Version:    "2.0",              // note: matches parent package
					},
					Parent: nil,
				},
			},
			expectedPackage: nil,
		},
		{
			name: "child matches parent by artifact id",
			props: pkg.JavaPomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-parent-name",       // note: matches parent package
				Version:    "NOT_THE_PARENT_VERSION", // note: DOES NOT match parent package
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath:   virtualPath + ":NEW_VIRTUAL_PATH", // note: DOES NOT match the existing virtual path
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			// note: the SAME as the original parent values
			expectedParent: pkg.Package{
				Name:    "some-parent-name",
				Version: "NOT_THE_PARENT_VERSION", // note: the version is updated from pom properties
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: virtualPath + ":NEW_VIRTUAL_PATH",
					Manifest:    nil,
					// note: we attach the discovered pom properties data
					PomProperties: &pkg.JavaPomProperties{
						Name:       "some-name",
						GroupID:    "some-group-id",
						ArtifactID: "some-parent-name",
						Version:    "NOT_THE_PARENT_VERSION",
					},
					Parent: nil,
				},
			},
			expectedPackage: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			locations := file.NewLocationSet(file.NewLocation(virtualPath))
			if test.expectedPackage != nil {
				test.expectedPackage.Locations = locations
				if test.expectedPackage.Metadata.(pkg.JavaArchive).Parent != nil {
					test.expectedPackage.Metadata.(pkg.JavaArchive).Parent.Locations = locations
				}
			}
			if test.parent != nil {
				test.parent.Locations = locations
			}
			test.expectedParent.Locations = locations

			r := maven.NewResolver(nil, maven.DefaultConfig())
			actualPackage := newPackageFromMavenData(context.Background(), r, test.props, test.project, test.parent, file.NewLocation(virtualPath))
			if test.expectedPackage == nil {
				require.Nil(t, actualPackage)
			} else {
				pkgtest.AssertPackagesEqual(t, *test.expectedPackage, *actualPackage)
			}

			pkgtest.AssertPackagesEqual(t, test.expectedParent, *test.parent)
		})
	}
}

func Test_artifactIDMatchesFilename(t *testing.T) {
	tests := []struct {
		name       string
		artifactID string
		fileName   string // without version or extension
		want       bool
	}{
		{
			name:       "artifact id within file name",
			artifactID: "atlassian-extras-api",
			fileName:   "com.atlassian.extras_atlassian-extras-api",
			want:       true,
		},
		{
			name:       "file name within artifact id",
			artifactID: "atlassian-extras-api-something",
			fileName:   "atlassian-extras-api",
			want:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, artifactIDMatchesFilename(tt.artifactID, tt.fileName, nil))
		})
	}
}

func Test_parseJavaArchive_regressions(t *testing.T) {
	apiAll := pkg.Package{
		Name:      "api-all",
		Version:   "2.0.0",
		Type:      pkg.JavaPkg,
		Language:  pkg.Java,
		PURL:      "pkg:maven/org.apache.directory.api/api-all@2.0.0",
		Locations: file.NewLocationSet(file.NewLocation("test-fixtures/jar-metadata/cache/api-all-2.0.0-sources.jar")),
		Metadata: pkg.JavaArchive{
			VirtualPath: "test-fixtures/jar-metadata/cache/api-all-2.0.0-sources.jar",
			Manifest: &pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Manifest-Version",
						Value: "1.0",
					},
					{
						Key:   "Built-By",
						Value: "elecharny",
					},
					{
						Key:   "Created-By",
						Value: "Apache Maven 3.6.0",
					},
					{
						Key:   "Build-Jdk",
						Value: "1.8.0_191",
					},
				},
			},
			PomProperties: &pkg.JavaPomProperties{
				Path:       "META-INF/maven/org.apache.directory.api/api-all/pom.properties",
				GroupID:    "org.apache.directory.api",
				ArtifactID: "api-all",
				Version:    "2.0.0",
			},
		},
	}

	apiAsn1Api := pkg.Package{
		Name:      "api-asn1-api",
		Version:   "2.0.0",
		PURL:      "pkg:maven/org.apache.directory.api/api-asn1-api@2.0.0",
		Locations: file.NewLocationSet(file.NewLocation("test-fixtures/jar-metadata/cache/api-all-2.0.0-sources.jar")),
		Type:      pkg.JavaPkg,
		Language:  pkg.Java,
		Metadata: pkg.JavaArchive{
			VirtualPath: "test-fixtures/jar-metadata/cache/api-all-2.0.0-sources.jar:org.apache.directory.api:api-asn1-api",
			PomProperties: &pkg.JavaPomProperties{
				Path:       "META-INF/maven/org.apache.directory.api/api-asn1-api/pom.properties",
				GroupID:    "org.apache.directory.api",
				ArtifactID: "api-asn1-api",
				Version:    "2.0.0",
			},
			PomProject: &pkg.JavaPomProject{
				Path:        "META-INF/maven/org.apache.directory.api/api-asn1-api/pom.xml",
				ArtifactID:  "api-asn1-api",
				GroupID:     "org.apache.directory.api",
				Version:     "2.0.0",
				Name:        "Apache Directory API ASN.1 API",
				Description: "ASN.1 API",
				Parent: &pkg.JavaPomParent{
					GroupID:    "org.apache.directory.api",
					ArtifactID: "api-asn1-parent",
					Version:    "2.0.0",
				},
			},
			Parent: &apiAll,
		},
	}

	tests := []struct {
		name                  string
		fixtureName           string
		fileExtension         string
		expectedPkgs          []pkg.Package
		expectedRelationships []artifact.Relationship
		assignParent          bool
	}{
		{
			name:        "duplicate jar regression - go case (issue #2130)",
			fixtureName: "jackson-core-2.15.2",
			expectedPkgs: []pkg.Package{
				{
					Name:      "jackson-core",
					Version:   "2.15.2",
					Type:      pkg.JavaPkg,
					Language:  pkg.Java,
					PURL:      "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.2",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/jar-metadata/cache/jackson-core-2.15.2.jar")),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicensesFromLocation(
							file.NewLocation("test-fixtures/jar-metadata/cache/jackson-core-2.15.2.jar"),
							"https://www.apache.org/licenses/LICENSE-2.0.txt",
						)...,
					),
					Metadata: pkg.JavaArchive{
						VirtualPath: "test-fixtures/jar-metadata/cache/jackson-core-2.15.2.jar",
						Manifest: &pkg.JavaManifest{
							Main: pkg.KeyValues{
								{Key: "Manifest-Version", Value: "1.0"},
								{Key: "Bundle-License", Value: "https://www.apache.org/licenses/LICENSE-2.0.txt"},
								{Key: "Bundle-SymbolicName", Value: "com.fasterxml.jackson.core.jackson-core"},
								{Key: "Implementation-Vendor-Id", Value: "com.fasterxml.jackson.core"},
								{Key: "Specification-Title", Value: "Jackson-core"},
								{Key: "Bundle-DocURL", Value: "https://github.com/FasterXML/jackson-core"},
								{Key: "Import-Package", Value: "com.fasterxml.jackson.core;version=...snip"},
								{Key: "Require-Capability", Value: `osgi.ee;filter:="(&(osgi.ee=JavaSE)(version=1.8))"`},
								{Key: "Export-Package", Value: "com.fasterxml.jackson.core;version...snip"},
								{Key: "Bundle-Name", Value: "Jackson-core"},
								{Key: "Multi-Release", Value: "true"},
								{Key: "Build-Jdk-Spec", Value: "1.8"},
								{Key: "Bundle-Description", Value: "Core Jackson processing abstractions"},
								{Key: "Implementation-Title", Value: "Jackson-core"},
								{Key: "Implementation-Version", Value: "2.15.2"},
								{Key: "Bundle-ManifestVersion", Value: "2"},
								{Key: "Specification-Vendor", Value: "FasterXML"},
								{Key: "Bundle-Vendor", Value: "FasterXML"},
								{Key: "Tool", Value: "Bnd-6.3.1.202206071316"},
								{Key: "Implementation-Vendor", Value: "FasterXML"},
								{Key: "Bundle-Version", Value: "2.15.2"},
								{Key: "X-Compile-Target-JDK", Value: "1.8"},
								{Key: "X-Compile-Source-JDK", Value: "1.8"},
								{Key: "Created-By", Value: "Apache Maven Bundle Plugin 5.1.8"},
								{Key: "Specification-Version", Value: "2.15.2"},
							},
						},
						// not under test
						//ArchiveDigests: []file.Digest{{Algorithm: "sha1", Value: "d8bc1d9c428c96fe447e2c429fc4304d141024df"}},
					},
				},
			},
		},
		{
			name:        "duplicate jar regression - bad case (issue #2130)",
			fixtureName: "com.fasterxml.jackson.core.jackson-core-2.15.2",
			expectedPkgs: []pkg.Package{
				{
					Name:      "jackson-core",
					Version:   "2.15.2",
					Type:      pkg.JavaPkg,
					Language:  pkg.Java,
					PURL:      "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.2",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/jar-metadata/cache/com.fasterxml.jackson.core.jackson-core-2.15.2.jar")),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicensesFromLocation(
							file.NewLocation("test-fixtures/jar-metadata/cache/com.fasterxml.jackson.core.jackson-core-2.15.2.jar"),
							"https://www.apache.org/licenses/LICENSE-2.0.txt",
						)...,
					),
					Metadata: pkg.JavaArchive{
						VirtualPath: "test-fixtures/jar-metadata/cache/com.fasterxml.jackson.core.jackson-core-2.15.2.jar",
						Manifest: &pkg.JavaManifest{
							Main: pkg.KeyValues{
								{Key: "Manifest-Version", Value: "1.0"},
								{Key: "Bundle-License", Value: "https://www.apache.org/licenses/LICENSE-2.0.txt"},
								{Key: "Bundle-SymbolicName", Value: "com.fasterxml.jackson.core.jackson-core"},
								{Key: "Implementation-Vendor-Id", Value: "com.fasterxml.jackson.core"},
								{Key: "Specification-Title", Value: "Jackson-core"},
								{Key: "Bundle-DocURL", Value: "https://github.com/FasterXML/jackson-core"},
								{Key: "Import-Package", Value: "com.fasterxml.jackson.core;version=...snip"},
								{Key: "Require-Capability", Value: `osgi.ee;filter:="(&(osgi.ee=JavaSE)(version=1.8))"`},
								{Key: "Export-Package", Value: "com.fasterxml.jackson.core;version...snip"},
								{Key: "Bundle-Name", Value: "Jackson-core"},
								{Key: "Multi-Release", Value: "true"},
								{Key: "Build-Jdk-Spec", Value: "1.8"},
								{Key: "Bundle-Description", Value: "Core Jackson processing abstractions"},
								{Key: "Implementation-Title", Value: "Jackson-core"},
								{Key: "Implementation-Version", Value: "2.15.2"},
								{Key: "Bundle-ManifestVersion", Value: "2"},
								{Key: "Specification-Vendor", Value: "FasterXML"},
								{Key: "Bundle-Vendor", Value: "FasterXML"},
								{Key: "Tool", Value: "Bnd-6.3.1.202206071316"},
								{Key: "Implementation-Vendor", Value: "FasterXML"},
								{Key: "Bundle-Version", Value: "2.15.2"},
								{Key: "X-Compile-Target-JDK", Value: "1.8"},
								{Key: "X-Compile-Source-JDK", Value: "1.8"},
								{Key: "Created-By", Value: "Apache Maven Bundle Plugin 5.1.8"},
								{Key: "Specification-Version", Value: "2.15.2"},
							},
						},
						// not under test
						//ArchiveDigests: []file.Digest{{Algorithm: "sha1", Value: "abd3e329270fc54a2acaceb45420fd5710ecefd5"}},
					},
				},
			},
		},
		{
			name:         "multiple pom for parent selection regression (pr 2231)",
			fixtureName:  "api-all-2.0.0-sources",
			assignParent: true,
			expectedPkgs: []pkg.Package{
				apiAll,
				apiAsn1Api,
			},
			expectedRelationships: []artifact.Relationship{
				{
					From: apiAsn1Api,
					To:   apiAll,
					Type: artifact.DependencyOfRelationship,
				},
			},
		},
		{
			name:         "exclude instrumentation jars with Weave-Classes in manifest",
			fixtureName:  "spring-instrumentation-4.3.0-1.0",
			expectedPkgs: nil, // we expect no packages to be discovered when Weave-Classes present in the manifest
		},
		{
			name:          "Jenkins plugins assigned jenkins-plugin package type",
			fixtureName:   "gradle",
			fileExtension: "hpi",
			expectedPkgs: []pkg.Package{
				{
					Name:      "gradle",
					Version:   "2.11",
					Type:      pkg.JenkinsPluginPkg,
					Language:  pkg.Java,
					PURL:      "pkg:maven/org.jenkins-ci.plugins/gradle@2.11",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/jar-metadata/cache/gradle.hpi")),
					Metadata: pkg.JavaArchive{
						VirtualPath: "test-fixtures/jar-metadata/cache/gradle.hpi",
						Manifest: &pkg.JavaManifest{
							Main: pkg.KeyValues{
								{Key: "Manifest-Version", Value: "1.0"},
								{
									Key:   "Plugin-Dependencies",
									Value: "maven-plugin:3.14;resolution:=optional...snip",
								},
								{Key: "Group-Id", Value: "org.jenkins-ci.plugins"},
								{Key: "Minimum-Java-Version", Value: "1.8"},
								{Key: "Short-Name", Value: "gradle"},
								{Key: "Extension-Name", Value: "gradle"},
								{Key: "Long-Name", Value: "Gradle Plugin"},
								{Key: "Jenkins-Version", Value: "2.303.3"},
								{Key: "Url", Value: "https://github.com/jenkinsci/gradle-plugin"},
								{Key: "Compatible-Since-Version", Value: "1.0"},
								{Key: "Plugin-Version", Value: "2.11"},
								{Key: "Plugin-Developers", Value: "Stefan Wolf:wolfs:"},
							},
						},
						// not under test
						//ArchiveDigests: []file.Digest{{Algorithm: "sha1", Value: "d8bc1d9c428c96fe447e2c429fc4304d141024df"}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gap := newGenericArchiveParserAdapter(ArchiveCatalogerConfig{})
			if tt.assignParent {
				assignParent(&tt.expectedPkgs[0], tt.expectedPkgs[1:]...)
			}
			for i := range tt.expectedPkgs {
				tt.expectedPkgs[i].SetID()
			}
			pkgtest.NewCatalogTester().
				FromFile(t, generateJavaMetadataJarFixture(t, tt.fixtureName, tt.fileExtension)).
				Expects(tt.expectedPkgs, tt.expectedRelationships).
				WithCompareOptions(
					cmpopts.IgnoreFields(pkg.JavaArchive{}, "ArchiveDigests"),
					cmp.Comparer(func(x, y pkg.KeyValue) bool {
						if x.Key != y.Key {
							return false
						}
						if x.Value != y.Value {
							return false
						}

						return true
					}),
				).
				TestParser(t, gap.parseJavaArchive)
		})
	}
}

func Test_deterministicMatchingPomProperties(t *testing.T) {
	ctx := licenses.SetContextLicenseScanner(context.Background(), licenses.TestingOnlyScanner())

	tests := []struct {
		fixture  string
		expected maven.ID
	}{
		{
			fixture:  "multiple-matching-2.11.5",
			expected: maven.NewID("org.multiple", "multiple-matching-1", "2.11.5"),
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			fixturePath := generateJavaMetadataJarFixture(t, test.fixture, "jar")

			for i := 0; i < 5; i++ {
				func() {
					fixture, err := os.Open(fixturePath)
					require.NoError(t, err)

					parser, cleanupFn, err := newJavaArchiveParser(
						ctx,
						file.LocationReadCloser{
							Location:   file.NewLocation(fixture.Name()),
							ReadCloser: fixture,
						}, false, ArchiveCatalogerConfig{UseNetwork: false})
					defer cleanupFn()
					require.NoError(t, err)

					groupID, artifactID, version, _ := parser.discoverMainPackageFromPomInfo(context.TODO())
					require.Equal(t, test.expected, maven.NewID(groupID, artifactID, version))
				}()
			}
		})
	}
}

func assignParent(parent *pkg.Package, childPackages ...pkg.Package) {
	for i, jp := range childPackages {
		if v, ok := jp.Metadata.(pkg.JavaArchive); ok {
			v.Parent = parent
			childPackages[i].Metadata = v
		}
	}
}

func generateJavaBuildFixture(t *testing.T, fixturePath string) {
	if _, err := os.Stat(fixturePath); !os.IsNotExist(err) {
		// fixture already exists...
		return
	}

	makeTask := strings.TrimPrefix(fixturePath, "test-fixtures/java-builds/")
	t.Logf(color.Bold.Sprintf("Generating Fixture from 'make %s'", makeTask))

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}

	cmd := exec.Command("make", makeTask)
	cmd.Dir = filepath.Join(cwd, "test-fixtures/java-builds/")

	run(t, cmd)
}

func generateJavaMetadataJarFixture(t *testing.T, fixtureName string, fileExtension string) string {
	if fileExtension == "" {
		fileExtension = "jar"
	}

	fixturePath := filepath.Join("test-fixtures/jar-metadata/cache/", fixtureName+"."+fileExtension)
	if _, err := os.Stat(fixturePath); !os.IsNotExist(err) {
		// fixture already exists...
		return fixturePath
	}

	makeTask := filepath.Join("cache", fixtureName+"."+fileExtension)
	t.Logf(color.Bold.Sprintf("Generating Fixture from 'make %s'", makeTask))

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}

	cmd := exec.Command("make", makeTask)
	cmd.Dir = filepath.Join(cwd, "test-fixtures/jar-metadata")

	run(t, cmd)

	return fixturePath
}

func run(t testing.TB, cmd *exec.Cmd) {

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("could not get stderr: %+v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("could not get stdout: %+v", err)
	}

	err = cmd.Start()
	if err != nil {
		t.Fatalf("failed to start cmd: %+v", err)
	}

	show := func(label string, reader io.ReadCloser) {
		scanner := bufio.NewScanner(reader)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			t.Logf("%s: %s", label, scanner.Text())
		}
	}
	go show("out", stdout)
	go show("err", stderr)

	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0

			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				if status.ExitStatus() != 0 {
					t.Fatalf("failed to generate fixture: rc=%d", status.ExitStatus())
				}
			}
		} else {
			t.Fatalf("unable to get generate fixture result: %+v", err)
		}
	}
}

// ptr returns a pointer to the given value
func ptr[T any](value T) *T {
	return &value
}

func Test_corruptJarArchive(t *testing.T) {
	ap := newGenericArchiveParserAdapter(DefaultArchiveCatalogerConfig())
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/example.jar").
		WithError().
		TestParser(t, ap.parseJavaArchive)
}
