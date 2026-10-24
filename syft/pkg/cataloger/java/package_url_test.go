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
					VirtualPath: "testdata/java-builds/packages/example-java-app-maven-0.1.0.jar",
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
					VirtualPath: "testdata/java-builds/packages/example-java-app-maven-0.1.0.jar",
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
					VirtualPath: "testdata/java-builds/packages/example-java-app-maven-0.1.0.jar",
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
					VirtualPath: "testdata/java-builds/packages/example-java-app-maven-0.1.0.jar",
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
		{
			// regression for github.com/anchore/syft/issues/5311
			name: "groovy 4 without pom metadata",
			pkg: pkg.Package{
				Name:     "groovy",
				Version:  "4.0.33",
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					VirtualPath: "groovy-4.0.33.jar",
					Manifest: &pkg.JavaManifest{
						Main: []pkg.KeyValue{
							{Key: "Bundle-SymbolicName", Value: "groovy"},
							{Key: "Automatic-Module-Name", Value: "org.apache.groovy.core"},
						},
					},
				},
			},
			expect: "pkg:maven/org.apache.groovy/groovy@4.0.33",
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
		version  string
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
			// regression for github.com/anchore/syft/issues/4030: spring-ldap artifacts
			// live under org.springframework.ldap, not org.springframework
			name:     "known package list spring-ldap-core",
			pkgName:  "spring-ldap-core",
			metadata: pkg.JavaArchive{},
			expect:   "org.springframework.ldap",
		},
		{
			name:     "known package list spring-ldap",
			pkgName:  "spring-ldap",
			metadata: pkg.JavaArchive{},
			expect:   "org.springframework.ldap",
		},
		{
			// regression for github.com/anchore/syft/issues/4598: legacy Jackson 1.x ("-asl")
			// jars built before ~2014 have no embedded pom.properties, so without the known
			// package list the group ID falls back to the artifact name itself, producing a
			// purl that doesn't match the vulnerability database's namespace (e.g. the correct
			// group for jackson-mapper-asl is org.codehaus.jackson, not jackson-mapper-asl).
			name:     "known package list jackson-mapper-asl",
			pkgName:  "jackson-mapper-asl",
			metadata: pkg.JavaArchive{},
			expect:   "org.codehaus.jackson",
		},
		{
			name:     "known package list jackson-core-asl",
			pkgName:  "jackson-core-asl",
			metadata: pkg.JavaArchive{},
			expect:   "org.codehaus.jackson",
		},
		{
			// regression: Apache Derby jars are OSGi bundles that ship no pom
			// metadata, so the manifest heuristic would otherwise pick up
			// Bundle-Activator (org.apache.derby.osgi.EmbeddedActivator) as the
			// group ID. The known package list must win instead.
			name:     "known package list derby",
			pkgName:  "derby",
			metadata: pkg.JavaArchive{},
			expect:   "org.apache.derby",
		},
		{
			name:     "known package list derbytools",
			pkgName:  "derbytools",
			metadata: pkg.JavaArchive{},
			expect:   "org.apache.derby",
		},
		{
			// regression for github.com/anchore/syft/issues/5311: groovy 4+ moved to org.apache.groovy, but
			// jars without pom metadata fall through to the known package list, which keeps the codehaus-era
			// coordinates. The map must also beat the per-module Automatic-Module-Name in the manifest.
			name:    "known package list groovy 4 beats the manifest",
			pkgName: "groovy",
			version: "4.0.33",
			metadata: pkg.JavaArchive{
				Manifest: &pkg.JavaManifest{
					Main: []pkg.KeyValue{
						{Key: "Bundle-SymbolicName", Value: "groovy"},
						{Key: "Automatic-Module-Name", Value: "org.apache.groovy.core"},
					},
				},
			},
			expect: "org.apache.groovy",
		},
		{
			// modules only published under the apache coordinates would otherwise take the group ID
			// from the per-module Automatic-Module-Name (org.apache.groovy.ginq)
			name:    "known package list apache-only groovy module",
			pkgName: "groovy-ginq",
			version: "4.0.33",
			metadata: pkg.JavaArchive{
				Manifest: &pkg.JavaManifest{
					Main: []pkg.KeyValue{
						{Key: "Automatic-Module-Name", Value: "org.apache.groovy.ginq"},
					},
				},
			},
			expect: "org.apache.groovy",
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
			assert.Equal(t, tt.expect, groupIDFromJavaMetadata(tt.pkgName, tt.version, tt.metadata))
		})
	}
}
