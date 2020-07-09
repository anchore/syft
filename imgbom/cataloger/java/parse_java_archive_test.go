package java

import (
	"bufio"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/go-test/deep"
	"github.com/gookit/color"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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
			fixture:      "test-fixtures/java-builds/packages/example-jenkins-plugin.hpi",
			ignoreExtras: []string{"Plugin-Version"}, // has dynamic date
			expected: map[string]pkg.Package{
				"example-jenkins-plugin": {
					Name:     "example-jenkins-plugin",
					Version:  "1.0-SNAPSHOT",
					Language: pkg.Java,
					Type:     pkg.JenkinsPluginPkg,
					Metadata: pkg.JavaMetadata{
						Manifest: &pkg.JavaManifest{
							ManifestVersion: "1.0",
							SpecTitle:       "The Jenkins Plugins Parent POM Project",
							ImplTitle:       "example-jenkins-plugin",
							ImplVersion:     "1.0-SNAPSHOT",
							Extra: map[string]string{
								"Archiver-Version":     "Plexus Archiver",
								"Plugin-License-Url":   "https://opensource.org/licenses/MIT",
								"Plugin-License-Name":  "MIT License",
								"Created-By":           "Apache Maven",
								"Built-By":             "?",
								"Build-Jdk":            "14.0.1",
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
					Name:     "example-java-app-gradle",
					Version:  "0.1.0",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
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
			expected: map[string]pkg.Package{
				"example-java-app-maven": {
					Name:     "example-java-app-maven",
					Version:  "0.1.0",
					Language: pkg.Java,
					Type:     pkg.JavaPkg,
					Metadata: pkg.JavaMetadata{
						Manifest: &pkg.JavaManifest{
							ManifestVersion: "1.0",
							Extra: map[string]string{
								"Archiver-Version": "Plexus Archiver",
								"Created-By":       "Apache Maven 3.6.3",
								"Built-By":         "?",
								"Build-Jdk":        "14.0.1",
								"Main-Class":       "hello.HelloWorld",
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
					Name:     "joda-time",
					Version:  "2.9.2",
					Language: pkg.Java,
					Type:     pkg.UnknownPkg,
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

			actual, err := parseJavaArchive(fixture.Name(), fixture)
			if err != nil {
				t.Fatalf("failed to parse java archive: %+v", err)
			}

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", len(actual), 1)
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
					delete(metadata.Manifest.Extra, field)
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
