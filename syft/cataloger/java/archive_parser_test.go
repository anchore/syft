package java

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
	"github.com/gookit/color"
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

func TestSelectName(t *testing.T) {
	tests := []struct {
		desc     string
		manifest pkg.JavaManifest
		archive  archiveFilename
		expected string
	}{
		{
			desc:    "name from Implementation-Title",
			archive: archiveFilename{},
			manifest: pkg.JavaManifest{
				Name:      "",
				SpecTitle: "",
				ImplTitle: "maven-wrapper",
			},
			expected: "maven-wrapper",
		},
		{
			desc: "Implementation-Title does not override",
			manifest: pkg.JavaManifest{
				Name:      "Foo",
				SpecTitle: "",
				ImplTitle: "maven-wrapper",
			},
			archive: archiveFilename{
				fields: []map[string]string{
					{"name": "omg"},
				},
			},
			expected: "omg",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			result := selectName(&test.manifest, test.archive)

			if result != test.expected {
				t.Errorf("mismatch in names: '%s' != '%s'", result, test.expected)
			}
		})
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
				"Build-Jdk",      // can't guarantee the JDK used at build time
			},
			expected: map[string]pkg.Package{
				"example-jenkins-plugin": {
					Name:         "example-jenkins-plugin",
					Version:      "1.0-SNAPSHOT",
					Language:     pkg.Java,
					Type:         pkg.JenkinsPluginPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						Manifest: &pkg.JavaManifest{
							ManifestVersion: "1.0",
							SpecTitle:       "The Jenkins Plugins Parent POM Project",
							ImplTitle:       "example-jenkins-plugin",
							ImplVersion:     "1.0-SNAPSHOT",
							Extra: map[string]string{
								"Archiver-Version":    "Plexus Archiver",
								"Plugin-License-Url":  "https://opensource.org/licenses/MIT",
								"Plugin-License-Name": "MIT License",
								"Created-By":          "Apache Maven",
								"Built-By":            "?",
								//"Build-Jdk":            "14.0.1",
								"Jenkins-Version":      "2.164.3",
								"Minimum-Java-Version": "1.8",
								"Plugin-Developers":    "",
								"Plugin-ScmUrl":        "https://github.com/jenkinsci/plugin-pom/example-jenkins-plugin",
								"Extension-Name":       "example-jenkins-plugin",
								"Short-Name":           "example-jenkins-plugin",
								"Group-Id":             "io.jenkins.plugins",
								"Plugin-Dependencies":  "structs:1.20",
								//"Plugin-Version": "1.0-SNAPSHOT (private-07/09/2020 13:30-?)",
								"Hudson-Version": "2.164.3",
								"Long-Name":      "TODO Plugin",
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
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						Manifest: &pkg.JavaManifest{
							ManifestVersion: "1.0",
						},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/java-builds/packages/example-java-app-maven-0.1.0.jar",
			ignoreExtras: []string{
				"Build-Jdk", // can't guarantee the JDK used at build time
			},
			expected: map[string]pkg.Package{
				"example-java-app-maven": {
					Name:         "example-java-app-maven",
					Version:      "0.1.0",
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						Manifest: &pkg.JavaManifest{
							ManifestVersion: "1.0",
							Extra: map[string]string{
								"Archiver-Version": "Plexus Archiver",
								"Created-By":       "Apache Maven 3.6.3",
								"Built-By":         "?",
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
					Language:     pkg.Java,
					Type:         pkg.JavaPkg,
					MetadataType: pkg.JavaMetadataType,
					Metadata: pkg.JavaMetadata{
						PomProperties: &pkg.PomProperties{
							Path:       "META-INF/maven/joda-time/joda-time/pom.properties",
							GroupID:    "joda-time",
							ArtifactID: "joda-time",
							Version:    "2.9.2",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {

			generateJavaBuildFixture(t, test.fixture)

			fixture, err := os.Open(test.fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			parser, cleanupFn, err := newJavaArchiveParser(fixture.Name(), fixture, false)
			defer cleanupFn()
			if err != nil {
				t.Fatalf("should not have filed... %+v", err)
			}

			actual, err := parser.parse()
			if err != nil {
				t.Fatalf("failed to parse java archive: %+v", err)
			}

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", len(actual), len(test.expected))
			}

			var parent *pkg.Package
			for _, a := range actual {
				if strings.Contains(a.Name, "example-") {
					parent = &a
				}
			}

			if parent == nil {
				t.Fatal("could not find the parent pkg")
			}

			for _, a := range actual {
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

				// ignore select fields
				for _, field := range test.ignoreExtras {
					if metadata.Manifest != nil && metadata.Manifest.Extra != nil {
						if _, ok := metadata.Manifest.Extra[field]; ok {
							delete(metadata.Manifest.Extra, field)
						}
					}
				}

				// write censored data back
				a.Metadata = metadata

				diffs := deep.Equal(a, e)
				if len(diffs) > 0 {
					t.Errorf("diffs found for %q", a.Name)
					for _, d := range diffs {
						t.Errorf("diff: %+v", d)
					}
				}
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
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			actual, err := parseJavaArchive(fixture.Name(), fixture)
			if err != nil {
				t.Fatalf("failed to parse java archive: %+v", err)
			}

			nameVersionPairSet := internal.NewStringSet()

			makeKey := func(p *pkg.Package) string {
				if p == nil {
					t.Fatal("cannot make key for nil pkg")
				}
				return fmt.Sprintf("%s|%s", p.Name, p.Version)
			}

			for _, e := range test.expected {
				nameVersionPairSet.Add(makeKey(&e))
			}

			if len(actual) != len(nameVersionPairSet) {
				for _, a := range actual {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", len(actual), len(nameVersionPairSet))
			}

			for _, a := range actual {
				actualKey := makeKey(&a)

				if !nameVersionPairSet.Contains(actualKey) {
					t.Errorf("unexpected pkg: %q", actualKey)
				}

				metadata := a.Metadata.(pkg.JavaMetadata)
				if actualKey == "spring-boot|0.0.1-SNAPSHOT" {
					if metadata.Parent != nil {
						t.Errorf("expected no parent for root pkg, got %q", makeKey(metadata.Parent))
					}
				} else {
					if metadata.Parent == nil {
						t.Errorf("unassigned error for pkg=%q", actualKey)
					} else if makeKey(metadata.Parent) != "spring-boot|0.0.1-SNAPSHOT" {
						// NB: this is a hard-coded condition to simplify the test harness
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
