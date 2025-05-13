package cpegenerate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
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
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
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
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
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
		groupID  string
		expected []string
	}{
		{
			groupID:  "org.sonatype.nexus",
			expected: []string{"sonatype", "nexus"},
		},
		{
			groupID:  "org.jenkins-ci.plugins",
			expected: []string{"jenkins-ci"},
		},
		{
			groupID:  "io.jenkins.plugins",
			expected: []string{"jenkins"},
		},
		{
			groupID:  "com.cloudbees.jenkins.plugins",
			expected: []string{"cloudbees", "jenkins"},
		},
		{
			groupID:  "com.atlassian.confluence.plugins",
			expected: []string{"atlassian", "confluence"},
		},
		{
			groupID:  "com.google.guava",
			expected: []string{"google", "guava"},
		},
	}
	for _, test := range tests {
		t.Run(test.groupID, func(t *testing.T) {
			assert.ElementsMatch(t, append(test.expected, test.groupID), vendorsFromGroupIDs([]string{test.groupID}).values(), "different vendors")
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
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "io.jenkins-ci.plugin.thing;version='[2,3)'",
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "clean # suffixes",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "org.elasticsearch.plugin#parent-join;6.8.15",
					},
				},
			},
			expects: []string{"org.elasticsearch.plugin"},
		},
		{
			name: "from artifactID",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						ArtifactID: "io.jenkins-ci.plugin.thing; version='[2,3)' ; org.something.else",
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from main Extension-Name field",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: pkg.KeyValues{
							{
								Key:   "Extension-Name",
								Value: "io.jenkins-ci.plugin.thing",
							},
						},
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from named section Extension-Name field",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Sections: []pkg.KeyValues{
							{
								{
									Key:   "Name",
									Value: "section",
								},
								{
									Key:   "Extension-Name",
									Value: "io.jenkins-ci.plugin.thing",
								},
							},
						},
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from main field - tier 1",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: []pkg.KeyValue{
							// positive cases
							// tier 1
							{Key: "Extension-Name", Value: "io.jenkins-ci.plugin.1"},
							{Key: "Specification-Vendor", Value: "io.jenkins-ci.plugin.2"},
							{Key: "Implementation-Vendor", Value: "io.jenkins-ci.plugin.3"},
							{Key: "Bundle-SymbolicName", Value: "io.jenkins-ci.plugin.4"},
							{Key: "Implementation-Vendor-Id", Value: "io.jenkins-ci.plugin.5"},
							{Key: "Implementation-Title", Value: "io.jenkins-ci.plugin.6"},
							{Key: "Bundle-Activator", Value: "io.jenkins-ci.plugin.7"},
							// tier 2
							{Key: "Automatic-Module-Name", Value: "io.jenkins-ci.plugin.8"},
							{Key: "Main-Class", Value: "io.jenkins-ci.plugin.9"},
							{Key: "Package", Value: "io.jenkins-ci.plugin.10"},
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
			},
		},
		{
			name: "from main field - tier 2",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: []pkg.KeyValue{
							// positive cases
							{Key: "Automatic-Module-Name", Value: "io.jenkins-ci.plugin.8"},
							{Key: "Main-Class", Value: "io.jenkins-ci.plugin.9"},
							{Key: "Package", Value: "io.jenkins-ci.plugin.10"},
						},
					},
				},
			},
			expects: []string{
				"io.jenkins-ci.plugin.8",
				"io.jenkins-ci.plugin.9",
				"io.jenkins-ci.plugin.10",
			},
		},
		{
			name: "from main field - negative cases",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: []pkg.KeyValue{
							// negative cases
							{Key: "Extension-Name", Value: "not.a-group.id"},
							{Key: "bogus", Value: "io.jenkins-ci.plugin.please-dont-find-me"},
						},
					},
				},
			},
			expects: nil,
		},
		{
			name: "from named section field - tier 1",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Sections: []pkg.KeyValues{
							{
								{
									Key:   "Name",
									Value: "section",
								},
								// positive cases
								// tier 1
								{
									Key:   "Extension-Name",
									Value: "io.jenkins-ci.plugin.1",
								},
								{
									Key:   "Specification-Vendor",
									Value: "io.jenkins-ci.plugin.2",
								},
								{
									Key:   "Implementation-Vendor",
									Value: "io.jenkins-ci.plugin.3",
								},
								{
									Key:   "Bundle-SymbolicName",
									Value: "io.jenkins-ci.plugin.4",
								},
								{
									Key:   "Implementation-Vendor-Id",
									Value: "io.jenkins-ci.plugin.5",
								},
								{
									Key:   "Implementation-Title",
									Value: "io.jenkins-ci.plugin.6",
								},
								{
									Key:   "Bundle-Activator",
									Value: "io.jenkins-ci.plugin.7",
								},
								// tier 2
								{
									Key:   "Automatic-Module-Name",
									Value: "io.jenkins-ci.plugin.8",
								},
								{
									Key:   "Main-Class",
									Value: "io.jenkins-ci.plugin.9",
								},
								{
									Key:   "Package",
									Value: "io.jenkins-ci.plugin.10",
								},
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
			},
		},
		{
			name: "from named section field - negative cases",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Sections: []pkg.KeyValues{
							{
								{
									Key:   "Name",
									Value: "section",
								},
								{
									Key:   "Extension-Name",
									Value: "not.a-group.id",
								},
								{
									Key:   "bogus",
									Value: "io.jenkins-ci.plugin.please-dont-find-me",
								},
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
				Metadata: pkg.JavaArchive{},
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
			assert.ElementsMatch(t, test.expects, GroupIDsFromJavaPackage(test.pkg))
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
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						ArtifactID: "cloudbees-installation-manager",
					},
				},
			},
			expects: "cloudbees-installation-manager",
		},
		{
			name: "ignore groupID-like things",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
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
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Sections: []pkg.KeyValues{
							{
								{
									Key:   "Name",
									Value: "section",
								},
								// positive cases
								{
									Key:   "Specification-Vendor",
									Value: "Alex Goodman",
								},
								{
									Key:   "Implementation-Vendor",
									Value: "William Goodman",
								},
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
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Sections: []pkg.KeyValues{
							{
								{
									Key:   "Name",
									Value: "section",
								},
								// negative cases

								{
									Key:   "Specification-Vendor",
									Value: "io.jenkins-ci.plugin.thing",
								},
								{
									Key:   "Implementation-Vendor-ID",
									Value: "William Goodman",
								},
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

func Test_groupIDsFromJavaManifest(t *testing.T) {
	tests := []struct {
		name     string
		manifest pkg.JavaManifest
		expected []string
	}{
		{
			name:     "spring-security-core",
			manifest: pkg.JavaManifest{},
			expected: []string{"org.springframework.security"},
		},
		{
			name:     "spring-web",
			manifest: pkg.JavaManifest{},
			expected: []string{"org.springframework"},
		},
		{
			name: "spring-foo",
			manifest: pkg.JavaManifest{
				Main: []pkg.KeyValue{
					{
						Key:   "Implementation-Vendor",
						Value: "org.foo",
					},
				},
			},
			expected: []string{"org.foo"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := groupIDsFromJavaManifest(test.name, &test.manifest)
			require.Equal(t, test.expected, got)
		})
	}
}
