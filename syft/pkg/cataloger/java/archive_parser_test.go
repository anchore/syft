package java

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gookit/color"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

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

func generateMockMavenHandler(responseFixture string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Set the Content-Type header to indicate that the response is XML
		w.Header().Set("Content-Type", "application/xml")
		// Copy the file's content to the response writer
		file, err := os.Open(responseFixture)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()
		_, err = io.Copy(w, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

type handlerPath struct {
	path    string
	handler func(w http.ResponseWriter, r *http.Request)
}

func TestSearchMavenForLicenses(t *testing.T) {
	mux, url, teardown := setup()
	defer teardown()
	tests := []struct {
		name             string
		fixture          string
		detectNested     bool
		config           ArchiveCatalogerConfig
		requestPath      string
		requestHandlers  []handlerPath
		expectedLicenses []pkg.License
	}{
		{
			name:         "searchMavenForLicenses returns the expected licenses when search is set to true",
			fixture:      "opensaml-core-3.4.6",
			detectNested: false,
			config: ArchiveCatalogerConfig{
				UseNetwork:              true,
				MavenBaseURL:            url,
				MaxParentRecursiveDepth: 2,
			},
			requestHandlers: []handlerPath{
				{
					path:    "/org/opensaml/opensaml-parent/3.4.6/opensaml-parent-3.4.6.pom",
					handler: generateMockMavenHandler("test-fixtures/maven-xml-responses/opensaml-parent-3.4.6.pom"),
				},
				{
					path:    "/net/shibboleth/parent/7.11.2/parent-7.11.2.pom",
					handler: generateMockMavenHandler("test-fixtures/maven-xml-responses/parent-7.11.2.pom"),
				},
			},
			expectedLicenses: []pkg.License{
				{
					Type:           license.Declared,
					Value:          `The Apache Software License, Version 2.0`,
					SPDXExpression: ``,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// configure maven central requests
			for _, hdlr := range tc.requestHandlers {
				mux.HandleFunc(hdlr.path, hdlr.handler)
			}

			// setup metadata fixture; note:
			// this fixture has a pomProjectObject and has a parent object
			// it has no licenses on either which is the condition for testing
			// the searchMavenForLicenses functionality
			jarName := generateJavaMetadataJarFixture(t, tc.fixture)
			fixture, err := os.Open(jarName)
			require.NoError(t, err)

			// setup parser
			ap, cleanupFn, err := newJavaArchiveParser(
				file.LocationReadCloser{
					Location:   file.NewLocation(fixture.Name()),
					ReadCloser: fixture,
				}, tc.detectNested, tc.config)
			defer cleanupFn()

			// assert licenses are discovered from upstream
			_, _, licenses := ap.guessMainPackageNameAndVersionFromPomInfo()
			assert.Equal(t, tc.expectedLicenses, licenses)
		})
	}
}

func TestFormatMavenURL(t *testing.T) {
	tests := []struct {
		name       string
		groupID    string
		artifactID string
		version    string
		expected   string
	}{
		{
			name:       "formatMavenURL correctly assembles the pom URL",
			groupID:    "org.springframework.boot",
			artifactID: "spring-boot-starter-test",
			version:    "3.1.5",
			expected:   "https://repo1.maven.org/maven2/org/springframework/boot/spring-boot-starter-test/3.1.5/spring-boot-starter-test-3.1.5.pom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requestURL, err := formatMavenPomURL(tc.groupID, tc.artifactID, tc.version, mavenBaseURL)
			assert.NoError(t, err, "expected no err; got %w", err)
			assert.Equal(t, tc.expected, requestURL)
		})
	}
}

func TestParseJar(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		expected     map[string]pkg.Package
		ignoreExtras []string
	}{
		{
			name:    "example-jenkins-plugin",
			fixture: "test-fixtures/java-builds/packages/example-jenkins-plugin.hpi",
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
							Main: map[string]string{
								"Manifest-Version":       "1.0",
								"Specification-Title":    "Example Jenkins Plugin",
								"Specification-Version":  "1.0",
								"Implementation-Title":   "Example Jenkins Plugin",
								"Implementation-Version": "1.0-SNAPSHOT",
								// extra fields...
								//"Archiver-Version":    "Plexus Archiver",
								"Plugin-License-Url":  "https://opensource.org/licenses/MIT",
								"Plugin-License-Name": "MIT License",
								"Created-By":          "Maven Archiver 3.6.0",
								//"Built-By":            "?",
								//"Build-Jdk":            "14.0.1",
								"Build-Jdk-Spec":  "18",
								"Jenkins-Version": "2.204",
								//"Minimum-Java-Version": "1.8",
								"Plugin-Developers": "",
								"Plugin-ScmUrl":     "https://github.com/jenkinsci/plugin-pom/example-jenkins-plugin",
								//"Extension-Name":      "example-jenkins-plugin",
								"Short-Name":          "example-jenkins-plugin",
								"Group-Id":            "io.jenkins.plugins",
								"Plugin-Dependencies": "structs:1.20",
								//"Plugin-Version": "1.0-SNAPSHOT (private-07/09/2020 13:30-?)",
								"Hudson-Version": "2.204",
								"Long-Name":      "Example Jenkins Plugin",
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
							Main: map[string]string{
								"Manifest-Version": "1.0",
								"Main-Class":       "hello.HelloWorld",
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
							Main: map[string]string{
								"Manifest-Version": "1.0",
								// extra fields...
								"Archiver-Version": "Plexus Archiver",
								"Created-By":       "Apache Maven 3.8.6",
								//"Built-By":         "?",
								//"Build-Jdk":        "14.0.1",
								"Main-Class": "hello.HelloWorld",
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

			parser, cleanupFn, err := newJavaArchiveParser(file.LocationReadCloser{
				Location:   file.NewLocation(fixture.Name()),
				ReadCloser: fixture,
			}, false, ArchiveCatalogerConfig{UseNetwork: false})
			defer cleanupFn()
			require.NoError(t, err)

			actual, _, err := parser.parse()
			require.NoError(t, err)

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", len(actual), len(test.expected))
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
						delete(metadata.Manifest.Main, field)
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

			actual, _, err := gap.parseJavaArchive(nil, nil, file.LocationReadCloser{
				Location:   file.NewLocation(fixture.Name()),
				ReadCloser: fixture,
			})
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
				JavaPomProject: &pkg.JavaPomProject{
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
				Licenses: []pkg.License{
					{
						Value:          "MIT",
						SPDXExpression: "MIT",
						Type:           license.Declared,
						URLs:           []string{"https://opensource.org/licenses/MIT"},
						Locations:      file.NewLocationSet(file.NewLocation("some-license-path")),
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
						Locations:      file.NewLocationSet(file.NewLocation("some-license-path")),
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

			actualPackage := newPackageFromMavenData(test.props, test.project, test.parent, file.NewLocation(virtualPath), DefaultArchiveCatalogerConfig())
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
			assert.Equal(t, tt.want, artifactIDMatchesFilename(tt.artifactID, tt.fileName))
		})
	}
}

func Test_parseJavaArchive_regressions(t *testing.T) {
	tests := []struct {
		name                  string
		fixtureName           string
		expectedPkgs          []pkg.Package
		expectedRelationships []artifact.Relationship
		assignParent          bool
		want                  bool
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
							Main: map[string]string{
								"Build-Jdk-Spec":           "1.8",
								"Bundle-Description":       "Core Jackson processing abstractions",
								"Bundle-DocURL":            "https://github.com/FasterXML/jackson-core",
								"Bundle-License":           "https://www.apache.org/licenses/LICENSE-2.0.txt",
								"Bundle-ManifestVersion":   "2",
								"Bundle-Name":              "Jackson-core",
								"Bundle-SymbolicName":      "com.fasterxml.jackson.core.jackson-core",
								"Bundle-Vendor":            "FasterXML",
								"Bundle-Version":           "2.15.2",
								"Created-By":               "Apache Maven Bundle Plugin 5.1.8",
								"Export-Package":           "com.fasterxml.jackson.core;version...snip",
								"Implementation-Title":     "Jackson-core",
								"Implementation-Vendor":    "FasterXML",
								"Implementation-Vendor-Id": "com.fasterxml.jackson.core",
								"Implementation-Version":   "2.15.2",
								"Import-Package":           "com.fasterxml.jackson.core;version=...snip",
								"Manifest-Version":         "1.0",
								"Multi-Release":            "true",
								"Require-Capability":       `osgi.ee;filter:="(&(osgi.ee=JavaSE)(version=1.8))"`,
								"Specification-Title":      "Jackson-core",
								"Specification-Vendor":     "FasterXML",
								"Specification-Version":    "2.15.2",
								"Tool":                     "Bnd-6.3.1.202206071316",
								"X-Compile-Source-JDK":     "1.8",
								"X-Compile-Target-JDK":     "1.8",
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
							Main: map[string]string{
								"Build-Jdk-Spec":           "1.8",
								"Bundle-Description":       "Core Jackson processing abstractions",
								"Bundle-DocURL":            "https://github.com/FasterXML/jackson-core",
								"Bundle-License":           "https://www.apache.org/licenses/LICENSE-2.0.txt",
								"Bundle-ManifestVersion":   "2",
								"Bundle-Name":              "Jackson-core",
								"Bundle-SymbolicName":      "com.fasterxml.jackson.core.jackson-core",
								"Bundle-Vendor":            "FasterXML",
								"Bundle-Version":           "2.15.2",
								"Created-By":               "Apache Maven Bundle Plugin 5.1.8",
								"Export-Package":           "com.fasterxml.jackson.core;version...snip",
								"Implementation-Title":     "Jackson-core",
								"Implementation-Vendor":    "FasterXML",
								"Implementation-Vendor-Id": "com.fasterxml.jackson.core",
								"Implementation-Version":   "2.15.2",
								"Import-Package":           "com.fasterxml.jackson.core;version=...snip",
								"Manifest-Version":         "1.0",
								"Multi-Release":            "true",
								"Require-Capability":       `osgi.ee;filter:="(&(osgi.ee=JavaSE)(version=1.8))"`,
								"Specification-Title":      "Jackson-core",
								"Specification-Vendor":     "FasterXML",
								"Specification-Version":    "2.15.2",
								"Tool":                     "Bnd-6.3.1.202206071316",
								"X-Compile-Source-JDK":     "1.8",
								"X-Compile-Target-JDK":     "1.8",
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
				{
					Name:      "api-all",
					Version:   "2.0.0",
					Type:      pkg.JavaPkg,
					Language:  pkg.Java,
					PURL:      "pkg:maven/org.apache.directory.api/api-all@2.0.0",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/jar-metadata/cache/api-all-2.0.0-sources.jar")),
					Metadata: pkg.JavaArchive{
						VirtualPath: "test-fixtures/jar-metadata/cache/api-all-2.0.0-sources.jar",
						Manifest: &pkg.JavaManifest{
							Main: map[string]string{
								"Build-Jdk":        "1.8.0_191",
								"Built-By":         "elecharny",
								"Created-By":       "Apache Maven 3.6.0",
								"Manifest-Version": "1.0",
							},
						},
						PomProperties: &pkg.JavaPomProperties{
							Path:       "META-INF/maven/org.apache.directory.api/api-all/pom.properties",
							GroupID:    "org.apache.directory.api",
							ArtifactID: "api-all",
							Version:    "2.0.0",
						},
					},
				},
				{
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
							Name:        "Apache Directory API ASN.1 API",
							Description: "ASN.1 API",
							Parent: &pkg.JavaPomParent{
								GroupID:    "org.apache.directory.api",
								ArtifactID: "api-asn1-parent",
								Version:    "2.0.0",
							},
						},
						Parent: nil,
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
			pkgtest.NewCatalogTester().
				FromFile(t, generateJavaMetadataJarFixture(t, tt.fixtureName)).
				Expects(tt.expectedPkgs, tt.expectedRelationships).
				WithCompareOptions(cmpopts.IgnoreFields(pkg.JavaArchive{}, "ArchiveDigests")).
				TestParser(t, gap.parseJavaArchive)
		})
	}
}

func assignParent(parent *pkg.Package, childPackages ...pkg.Package) {
	for i, jp := range childPackages {
		if v, ok := jp.Metadata.(pkg.JavaArchive); ok {
			parent := *parent
			// PURL are not calculated after the fact for parent
			parent.PURL = ""
			v.Parent = &parent
			childPackages[i].Metadata = v
		}
	}
}

func generateJavaMetadataJarFixture(t *testing.T, fixtureName string) string {
	fixturePath := filepath.Join("test-fixtures/jar-metadata/cache/", fixtureName+".jar")
	if _, err := os.Stat(fixturePath); !os.IsNotExist(err) {
		// fixture already exists...
		return fixturePath
	}

	makeTask := filepath.Join("cache", fixtureName+".jar")
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

// setup sets up a test HTTP server for mocking requests to maven central.
// The returned url is injected into the Config so the client uses the test server.
// Tests should register handlers on mux to simulate the expected request/response structure
func setup() (mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)
	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	return mux, server.URL, server.Close
}
