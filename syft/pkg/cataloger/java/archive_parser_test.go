package java

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/gookit/color"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
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

func TestParseJar(t *testing.T) {
	tests := []struct {
		fixture      string
		expected     map[string]pkg.Package
		ignoreExtras []string
	}{
		{
			fixture: "test-fixtures/java-builds/packages/example-jenkins-plugin.hpi",
			ignoreExtras: []string{
				"Plugin-Version", // has dynamic date
				"Built-By",       // podman returns the real UID
				"Build-Jdk",      // can't guarantee the JDK used at build time
			},
			expected: map[string]pkg.Package{
				"example-jenkins-plugin": {
					Name:         "example-jenkins-plugin",
					Version:      "1.0-SNAPSHOT",
					PURL:         "pkg:maven/io.jenkins.plugins/example-jenkins-plugin@1.0-SNAPSHOT",
					Licenses:     internal.LogicalStrings{Simple: []string{"MIT License"}},
					Language:     pkg.Java,
					Type:         pkg.JenkinsPluginPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
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
						PomProperties: &pkg.PomProperties{
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
			fixture: "test-fixtures/java-builds/packages/example-java-app-gradle-0.1.0.jar",
			expected: map[string]pkg.Package{
				"example-java-app-gradle": {
					Name:         "example-java-app-gradle",
					Version:      "0.1.0",
					PURL:         "pkg:maven/example-java-app-gradle/example-java-app-gradle@0.1.0",
					Licenses:     internal.LogicalStrings{},
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						VirtualPath: "test-fixtures/java-builds/packages/example-java-app-gradle-0.1.0.jar",
						Manifest: &pkg.JavaManifest{
							Main: map[string]string{
								"Manifest-Version": "1.0",
							},
						},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar",
			ignoreExtras: []string{
				"Build-Jdk", // can't guarantee the JDK used at build time
				"Built-By",  // podman returns the real UID
			},
			expected: map[string]pkg.Package{
				"example-java-app-maven": {
					Name:         "example-java-app-maven",
					Version:      "0.1.0",
					PURL:         "pkg:maven/org.anchore/example-java-app-maven@0.1.0",
					Licenses:     internal.LogicalStrings{},
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
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
						PomProperties: &pkg.PomProperties{
							Path:       "META-INF/maven/org.anchore/example-java-app-maven/pom.properties",
							GroupID:    "org.anchore",
							ArtifactID: "example-java-app-maven",
							Version:    "0.1.0",
						},
					},
				},
				"joda-time": {
					Name:         "joda-time",
					Version:      "2.9.2",
					PURL:         "pkg:maven/joda-time/joda-time@2.9.2",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						// ensure that nested packages with different names than that of the parent are appended as
						// a suffix on the virtual path
						VirtualPath: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar:joda-time",
						PomProperties: &pkg.PomProperties{
							Path:       "META-INF/maven/joda-time/joda-time/pom.properties",
							GroupID:    "joda-time",
							ArtifactID: "joda-time",
							Version:    "2.9.2",
						},
						PomProject: &pkg.PomProject{
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
		t.Run(path.Base(test.fixture), func(t *testing.T) {

			generateJavaBuildFixture(t, test.fixture)

			fixture, err := os.Open(test.fixture)
			require.NoError(t, err)

			for k := range test.expected {
				p := test.expected[k]
				p.Locations.Add(source.NewLocation(test.fixture))
				test.expected[k] = p
			}

			parser, cleanupFn, err := newJavaArchiveParser(source.LocationReadCloser{
				Location:   source.NewLocation(fixture.Name()),
				ReadCloser: fixture,
			}, false)
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

				if a.Name != parent.Name && a.Metadata.(pkg.JavaMetadata).Parent != nil && a.Metadata.(pkg.JavaMetadata).Parent.Name != parent.Name {
					t.Errorf("mismatched parent: %+v", a.Metadata.(pkg.JavaMetadata).Parent)
				}

				// we need to compare the other fields without parent attached
				metadata := a.Metadata.(pkg.JavaMetadata)
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

			actual, _, err := parseJavaArchive(nil, nil, source.LocationReadCloser{
				Location:   source.NewLocation(fixture.Name()),
				ReadCloser: fixture,
			})
			require.NoError(t, err)

			expectedNameVersionPairSet := internal.NewStringSet()

			makeKey := func(p *pkg.Package) string {
				if p == nil {
					t.Fatal("cannot make key for nil pkg")
				}
				return fmt.Sprintf("%s|%s", p.Name, p.Version)
			}

			for _, e := range test.expected {
				expectedNameVersionPairSet.Add(makeKey(&e))
			}

			actualNameVersionPairSet := internal.NewStringSet()
			for _, a := range actual {
				a := a
				key := makeKey(&a)
				actualNameVersionPairSet.Add(key)
				if !expectedNameVersionPairSet.Contains(key) {
					t.Errorf("extra package: %s", a)
				}
			}

			for _, key := range expectedNameVersionPairSet.ToSlice() {
				if !actualNameVersionPairSet.Contains(key) {
					t.Errorf("missing package: %s", key)
				}
			}

			if len(actual) != len(expectedNameVersionPairSet) {
				t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expectedNameVersionPairSet))
			}

			for _, a := range actual {
				a := a
				actualKey := makeKey(&a)

				metadata := a.Metadata.(pkg.JavaMetadata)
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
		props           pkg.PomProperties
		project         *pkg.PomProject
		parent          *pkg.Package
		expectedParent  pkg.Package
		expectedPackage *pkg.Package
	}{
		{
			name: "go case: get a single package from pom properties",
			props: pkg.PomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-artifact-id",
				Version:    "1.0",
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaMetadata{
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
				Metadata: pkg.JavaMetadata{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			expectedPackage: &pkg.Package{
				Name:         "some-artifact-id",
				Version:      "1.0",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					VirtualPath: virtualPath + ":" + "some-artifact-id",
					PomProperties: &pkg.PomProperties{
						Name:       "some-name",
						GroupID:    "some-group-id",
						ArtifactID: "some-artifact-id",
						Version:    "1.0",
					},
					Parent: &pkg.Package{
						Name:    "some-parent-name",
						Version: "2.0",
						Metadata: pkg.JavaMetadata{
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
			props: pkg.PomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-artifact-id",
				Version:    "1.0",
			},
			project: &pkg.PomProject{
				Parent: &pkg.PomParent{
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
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaMetadata{
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
				Metadata: pkg.JavaMetadata{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			expectedPackage: &pkg.Package{
				Name:         "some-artifact-id",
				Version:      "1.0",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					VirtualPath: virtualPath + ":" + "some-artifact-id",
					PomProperties: &pkg.PomProperties{
						Name:       "some-name",
						GroupID:    "some-group-id",
						ArtifactID: "some-artifact-id",
						Version:    "1.0",
					},
					PomProject: &pkg.PomProject{
						Parent: &pkg.PomParent{
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
						Metadata: pkg.JavaMetadata{
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
			props: pkg.PomProperties{
				Name:       "some-name",
				GroupID:    "com.cloudbees.jenkins.plugins",
				ArtifactID: "some-artifact-id",
				Version:    "1.0",
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Metadata: pkg.JavaMetadata{
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
				Metadata: pkg.JavaMetadata{
					VirtualPath:   "some-parent-virtual-path",
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			expectedPackage: &pkg.Package{
				Name:         "some-artifact-id",
				Version:      "1.0",
				Language:     pkg.Java,
				Type:         pkg.JenkinsPluginPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					VirtualPath: virtualPath + ":" + "some-artifact-id",
					PomProperties: &pkg.PomProperties{
						Name:       "some-name",
						GroupID:    "com.cloudbees.jenkins.plugins",
						ArtifactID: "some-artifact-id",
						Version:    "1.0",
					},
					Parent: &pkg.Package{
						Name:    "some-parent-name",
						Version: "2.0",
						Metadata: pkg.JavaMetadata{
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
			props: pkg.PomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-parent-name", // note: matches parent package
				Version:    "2.0",              // note: matches parent package
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
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
				Metadata: pkg.JavaMetadata{
					VirtualPath: "some-parent-virtual-path",
					Manifest:    nil,
					// note: we attach the discovered pom properties data
					PomProperties: &pkg.PomProperties{
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
			props: pkg.PomProperties{
				Name:       "some-name",
				GroupID:    "com.cloudbees.jenkins.plugins",
				ArtifactID: "some-parent-name", // note: matches parent package
				Version:    "2.0",              // note: matches parent package
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
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
				Metadata: pkg.JavaMetadata{
					VirtualPath: "some-parent-virtual-path",
					Manifest:    nil,
					// note: we attach the discovered pom properties data
					PomProperties: &pkg.PomProperties{
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
			name: "child matches parent by virtual path -- override name and version",
			props: pkg.PomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-parent-name", // note: DOES NOT match parent package
				Version:    "3.0",              // note: DOES NOT match parent package
			},
			parent: &pkg.Package{
				Name:    "", // note: empty, so should not be matched on
				Version: "", // note: empty, so should not be matched on
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
					VirtualPath:   virtualPath, // note: matching virtual path
					Manifest:      nil,
					PomProperties: nil,
					Parent:        nil,
				},
			},
			expectedParent: pkg.Package{
				Name:    "some-parent-name",
				Version: "3.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
					VirtualPath: virtualPath,
					Manifest:    nil,
					// note: we attach the discovered pom properties data
					PomProperties: &pkg.PomProperties{
						Name:       "some-name",
						GroupID:    "some-group-id",
						ArtifactID: "some-parent-name",
						Version:    "3.0",
					},
					Parent: nil,
				},
			},
			expectedPackage: nil,
		},
		{
			name: "child matches parent by artifact id",
			props: pkg.PomProperties{
				Name:       "some-name",
				GroupID:    "some-group-id",
				ArtifactID: "some-parent-name",       // note: matches parent package
				Version:    "NOT_THE_PARENT_VERSION", // note: DOES NOT match parent package
			},
			parent: &pkg.Package{
				Name:    "some-parent-name",
				Version: "2.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaMetadata{
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
				Metadata: pkg.JavaMetadata{
					VirtualPath: virtualPath + ":NEW_VIRTUAL_PATH",
					Manifest:    nil,
					// note: we attach the discovered pom properties data
					PomProperties: &pkg.PomProperties{
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
			locations := source.NewLocationSet(source.NewLocation(virtualPath))
			if test.expectedPackage != nil {
				test.expectedPackage.Locations = locations
				if test.expectedPackage.Metadata.(pkg.JavaMetadata).Parent != nil {
					test.expectedPackage.Metadata.(pkg.JavaMetadata).Parent.Locations = locations
				}
			}
			if test.parent != nil {
				test.parent.Locations = locations
			}
			test.expectedParent.Locations = locations

			actualPackage := newPackageFromMavenData(test.props, test.project, test.parent, source.NewLocation(virtualPath))
			if test.expectedPackage == nil {
				require.Nil(t, actualPackage)
			} else {
				pkgtest.AssertPackagesEqual(t, *test.expectedPackage, *actualPackage)
			}

			pkgtest.AssertPackagesEqual(t, test.expectedParent, *test.parent)
		})
	}
}
