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
		{
			groupIDs:   []string{"org.eclipse.jetty"},
			artifactID: "jetty-server",
			expected:   []string{"jetty-server", "jetty"},
		},
		{
			groupIDs:   []string{"org.eclipse.jetty.ee10"},
			artifactID: "jetty-ee10-servlet",
			expected:   []string{"jetty-ee10-servlet", "jetty"},
		},
		{
			groupIDs:   []string{"org.apache.tomcat.embed"},
			artifactID: "tomcat-embed-core",
			expected:   []string{"tomcat-embed-core", "tomcat"},
		},
		{
			// spring-boot vs springboot
			groupIDs:   []string{"org.apache.camel.springboot"},
			artifactID: "camel-spring-boot",
			expected:   []string{"camel-spring-boot", "camel"},
		},
		{
			groupIDs:   []string{"org.eclipse.jetty.toolchain"},
			artifactID: "jetty-schemas",
			expected:   []string{"jetty-schemas"},
		},
		{
			groupIDs:   []string{"org.eclipse.jetty.schemas"},
			artifactID: "jetty-schemas",
			expected:   []string{"jetty-schemas", "schemas"},
		},
		{
			groupIDs:   []string{"org.eclipse.jetty.toolchain.setuid"},
			artifactID: "jetty-setuid-java",
			expected:   []string{"jetty-setuid-java"},
		},
		{
			groupIDs:   []string{"org.eclipse.jetty.infinispan.common"},
			artifactID: "infinispan-common",
			expected:   []string{"infinispan-common", "common"},
		},
		{
			groupIDs:   []string{"org.apache.hadoop.thirdparty"},
			artifactID: "hadoop-shaded-guava",
			expected:   []string{"hadoop-shaded-guava"},
		},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.groupIDs, ",")+":"+test.artifactID, func(t *testing.T) {
			actual := productsFromArtifactAndGroupIDs(test.artifactID, test.groupIDs)
			assert.ElementsMatch(t, test.expected, actual, "different products")
		})
	}
}

func Test_belongsToGroupIDProject(t *testing.T) {
	tests := []struct {
		name       string
		artifactID string
		field      string
		nested     []string
		expected   bool
	}{
		{
			name:       "published directly under the project groupID",
			artifactID: "jetty-server",
			field:      "jetty",
			expected:   true,
		},
		{
			name:       "component naming its nested segment",
			artifactID: "jetty-ee10-servlet",
			field:      "jetty",
			nested:     []string{"ee10"},
			expected:   true,
		},
		{
			name:       "tomcat embed component",
			artifactID: "tomcat-embed-core",
			field:      "tomcat",
			nested:     []string{"embed"},
			expected:   true,
		},
		{
			name:       "component naming its nested segment with delimiters",
			artifactID: "camel-spring-boot",
			field:      "camel",
			nested:     []string{"springboot"},
			expected:   true,
		},
		{
			name:       "nested segment not acknowledged",
			artifactID: "jetty-schemas",
			field:      "jetty",
			nested:     []string{"toolchain"},
			expected:   false,
		},
		{
			name:       "artifact is the nested sub-project itself",
			artifactID: "jetty-schemas",
			field:      "jetty",
			nested:     []string{"schemas"},
			expected:   false,
		},
		{
			name:       "multiple nested segments, none acknowledged",
			artifactID: "jetty-setuid-java",
			field:      "jetty",
			nested:     []string{"toolchain", "setuid"},
			expected:   false,
		},
		{
			name:       "integration module is the nested sub-project itself",
			artifactID: "infinispan-common",
			field:      "infinispan",
			nested:     []string{"common"},
			expected:   false,
		},
		{
			name:       "shaded third-party repackaging",
			artifactID: "hadoop-shaded-guava",
			field:      "hadoop",
			nested:     []string{"thirdparty"},
			expected:   false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := belongsToGroupIDProject(test.artifactID, test.field, test.nested)
			assert.Equal(t, test.expected, actual)
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
		{
			// both gid sources yield "jetty"
			name: "artifact under a nested groupID does not claim the umbrella product",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "org.eclipse.jetty.toolchain",
						ArtifactID: "jetty-schemas",
					},
					Manifest: &pkg.JavaManifest{
						Main: pkg.KeyValues{
							{Key: "Bundle-Name", Value: "Jetty Servlet Schemas"},
							{Key: "Bundle-SymbolicName", Value: "org.eclipse.jetty.schemas;singleton:=true"},
							{Key: "Implementation-Vendor", Value: "Eclipse.org - Jetty"},
						},
					},
				},
			},
			expected: []string{"jetty-schemas", "schemas"},
		},
		{
			name: "genuine project component keeps the umbrella product",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "org.eclipse.jetty",
						ArtifactID: "jetty-server",
					},
					Manifest: &pkg.JavaManifest{
						Main: pkg.KeyValues{
							{Key: "Bundle-SymbolicName", Value: "org.eclipse.jetty.server"},
						},
					},
				},
			},
			expected: []string{"jetty-server", "jetty", "server"},
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
			name: "groupId correction properly applied",
			pkg: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: pkg.KeyValues{
							{
								Key:   "Automatic-Module-Name",
								Value: "org.lz4.java",
							},
						},
					},
				},
			},
			expects: []string{"org.lz4"},
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
			// pom-less groovy 4 jars (all real ones) must resolve to the apache group, same as the purl
			name: "groovy 4 without pom metadata",
			pkg: pkg.Package{
				Name:     "groovy",
				Version:  "4.0.33",
				Metadata: pkg.JavaArchive{Manifest: &pkg.JavaManifest{}},
			},
			expects: []string{"org.apache.groovy"},
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
			got := groupIDsFromJavaManifest(test.name, "", &test.manifest)
			require.Equal(t, test.expected, got)
		})
	}
}
