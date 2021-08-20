package cpe

import (
	"strings"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_productsFromArtifactAndGroupIDs(t *testing.T) {
	tests := []struct {
		groupIDs   []string
		artifactID string
		expected   []string
	}{
		{
			groupIDs:   []string{"org.sonatype.nexus"},
			artifactID: "nexus-extender",
			expected:   []string{"nexus", "nexus-extender"},
		},
		{
			groupIDs: []string{"org.sonatype.nexus"},
			expected: []string{"nexus"},
		},
		{
			groupIDs:   []string{"org.jenkins-ci.plugins"},
			artifactID: "ant",
			expected:   []string{"ant"},
		},
		{
			groupIDs:   []string{"org.jenkins-ci.plugins"},
			artifactID: "antisamy-markup-formatter",
			expected:   []string{"antisamy-markup-formatter"},
		},
		{
			groupIDs:   []string{"io.jenkins.plugins"},
			artifactID: "aws-global-configuration",
			expected:   []string{"aws-global-configuration"},
		},
		{
			groupIDs:   []string{"com.cloudbees.jenkins.plugins"},
			artifactID: "cloudbees-servicenow-jenkins-plugin",
			expected:   []string{"cloudbees-servicenow-jenkins-plugin"},
		},
		{
			groupIDs:   []string{"com.atlassian.confluence.plugins"},
			artifactID: "confluence-mobile-plugin",
			expected:   []string{"confluence-mobile-plugin"},
		},
		{
			groupIDs:   []string{"com.atlassian.confluence.plugins"},
			artifactID: "confluence-view-file-macro",
			expected:   []string{"confluence-view-file-macro"},
		},
		{
			groupIDs:   []string{"com.google.guava"},
			artifactID: "failureaccess",
			expected:   []string{"failureaccess"},
		},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.groupIDs, ",")+":"+test.artifactID, func(t *testing.T) {
			actual := productsFromArtifactAndGroupIDs(test.artifactID, test.groupIDs)
			assert.ElementsMatch(t, test.expected, actual, "different products")
		})
	}
}

func Test_candidateProductsForJava(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "duplicate groupID in artifactID field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID:    "org.sonatype.nexus",
						ArtifactID: "org.sonatype.nexus",
					},
				},
			},
			expected: []string{"nexus"},
		},
		{
			name: "detect groupID-like value in artifactID field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "org.sonatype.nexus",
					},
				},
			},
			expected: []string{"nexus"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := candidateProductsForJava(test.pkg)
			assert.ElementsMatch(t, test.expected, actual, "different products")
		})
	}
}

func Test_vendorsFromGroupIDs(t *testing.T) {
	tests := []struct {
		groupIDs []string
		expected []string
	}{
		{
			groupIDs: []string{"org.sonatype.nexus"},
			expected: []string{"sonatype", "nexus"},
		},
		{
			groupIDs: []string{"org.sonatype.nexus"},
			expected: []string{"sonatype", "nexus"},
		},
		{
			groupIDs: []string{"org.sonatype.nexus"},
			expected: []string{"sonatype", "nexus"},
		},
		{
			groupIDs: []string{"org.jenkins-ci.plugins"},
			expected: []string{"jenkins-ci", "jenkins"},
		},
		{
			groupIDs: []string{"org.jenkins-ci.plugins"},
			expected: []string{"jenkins-ci", "jenkins"},
		},
		{
			groupIDs: []string{"io.jenkins.plugins"},
			expected: []string{"jenkins"},
		},
		{
			groupIDs: []string{"com.cloudbees.jenkins.plugins"},
			expected: []string{"cloudbees", "jenkins"},
		},
		{
			groupIDs: []string{"com.atlassian.confluence.plugins"},
			expected: []string{"atlassian", "confluence"},
		},
		{
			groupIDs: []string{"com.atlassian.confluence.plugins"},
			expected: []string{"atlassian", "confluence"},
		},
		{
			groupIDs: []string{"com.google.guava"},
			expected: []string{"google", "guava"},
		},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.groupIDs, ","), func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, vendorsFromGroupIDs(test.groupIDs).values(), "different vendors")
		})
	}
}

func Test_groupIDsFromJavaPackage(t *testing.T) {
	tests := []struct {
		name    string
		pkg     pkg.Package
		expects []string
	}{
		{
			name: "go case",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "io.jenkins-ci.plugin.thing",
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from artifactID",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "io.jenkins-ci.plugin.thing",
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from main Extension-Name field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						Main: map[string]string{
							"Extension-Name": "io.jenkins-ci.plugin.thing",
						},
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from named section Extension-Name field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						NamedSections: map[string]map[string]string{
							"section": {
								"Extension-Name": "io.jenkins-ci.plugin.thing",
							},
						},
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from main field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						Main: map[string]string{
							// positive cases
							"Automatic-Module-Name":    "io.jenkins-ci.plugin.1",
							"Extension-Name":           "io.jenkins-ci.plugin.2",
							"Specification-Vendor":     "io.jenkins-ci.plugin.3",
							"Implementation-Vendor":    "io.jenkins-ci.plugin.4",
							"Bundle-SymbolicName":      "io.jenkins-ci.plugin.5",
							"Implementation-Vendor-Id": "io.jenkins-ci.plugin.6",
							"Package":                  "io.jenkins-ci.plugin.7",
							"Implementation-Title":     "io.jenkins-ci.plugin.8",
							"Main-Class":               "io.jenkins-ci.plugin.9",
							"Bundle-Activator":         "io.jenkins-ci.plugin.10",
						},
					},
				},
			},
			expects: []string{
				"io.jenkins-ci.plugin.1",
				"io.jenkins-ci.plugin.2",
				"io.jenkins-ci.plugin.3",
				"io.jenkins-ci.plugin.4",
				"io.jenkins-ci.plugin.5",
				"io.jenkins-ci.plugin.6",
				"io.jenkins-ci.plugin.7",
				"io.jenkins-ci.plugin.8",
				"io.jenkins-ci.plugin.9",
				"io.jenkins-ci.plugin.10",
			},
		},
		{
			name: "from main field - negative cases",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						Main: map[string]string{
							// negative cases
							"Extension-Name": "not.a-group.id",
							"bogus":          "io.jenkins-ci.plugin.please-dont-find-me",
						},
					},
				},
			},
			expects: nil,
		},
		{
			name: "from named section field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						NamedSections: map[string]map[string]string{
							"section": {
								// positive cases
								"Automatic-Module-Name":    "io.jenkins-ci.plugin.1",
								"Extension-Name":           "io.jenkins-ci.plugin.2",
								"Specification-Vendor":     "io.jenkins-ci.plugin.3",
								"Implementation-Vendor":    "io.jenkins-ci.plugin.4",
								"Bundle-SymbolicName":      "io.jenkins-ci.plugin.5",
								"Implementation-Vendor-Id": "io.jenkins-ci.plugin.6",
								"Package":                  "io.jenkins-ci.plugin.7",
								"Implementation-Title":     "io.jenkins-ci.plugin.8",
								"Main-Class":               "io.jenkins-ci.plugin.9",
								"Bundle-Activator":         "io.jenkins-ci.plugin.10",
							},
						},
					},
				},
			},
			expects: []string{
				"io.jenkins-ci.plugin.1",
				"io.jenkins-ci.plugin.2",
				"io.jenkins-ci.plugin.3",
				"io.jenkins-ci.plugin.4",
				"io.jenkins-ci.plugin.5",
				"io.jenkins-ci.plugin.6",
				"io.jenkins-ci.plugin.7",
				"io.jenkins-ci.plugin.8",
				"io.jenkins-ci.plugin.9",
				"io.jenkins-ci.plugin.10",
			},
		},
		{
			name: "from named section field - negative cases",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						NamedSections: map[string]map[string]string{
							"section": {
								// negative cases
								"Extension-Name": "not.a-group.id",
								"bogus":          "io.jenkins-ci.plugin.please-dont-find-me",
							},
						},
					},
				},
			},
			expects: nil,
		},
		{
			name: "no manifest or pom info",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{},
			},
			expects: nil,
		},
		{
			name:    "no java info",
			pkg:     pkg.Package{},
			expects: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expects, groupIDsFromJavaPackage(test.pkg))
		})
	}
}

func Test_artifactIDFromJavaPackage(t *testing.T) {
	tests := []struct {
		name    string
		pkg     pkg.Package
		expects string
	}{
		{
			name: "go case",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "cloudbees-installation-manager",
					},
				},
			},
			expects: "cloudbees-installation-manager",
		},
		{
			name: "ignore groupID-like things",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "io.jenkins-ci.plugin.thing",
					},
				},
			},
			expects: "",
		},
		{
			name:    "no java info",
			pkg:     pkg.Package{},
			expects: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expects, artifactIDFromJavaPackage(test.pkg))
		})
	}
}

func Test_vendorsFromJavaManifestNames(t *testing.T) {
	tests := []struct {
		name    string
		pkg     pkg.Package
		expects []string
	}{
		{
			name: "from manifest named section fields",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						NamedSections: map[string]map[string]string{
							"section": {
								// positive cases
								"Specification-Vendor":  "Alex Goodman",
								"Implementation-Vendor": "William Goodman",
							},
						},
					},
				},
			},
			expects: []string{"alex_goodman", "william_goodman"},
		},
		{
			name: "from manifest named section fields - negative cases",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						NamedSections: map[string]map[string]string{
							"section": {
								// negative cases
								"Specification-Vendor":     "io.jenkins-ci.plugin.thing",
								"Implementation-Vendor-ID": "William Goodman",
							},
						},
					},
				},
			},
			expects: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expects, vendorsFromJavaManifestNames(test.pkg).values())
		})
	}
}
