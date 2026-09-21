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
			// Groovy 4.0 moved from the Codehaus coordinates to the Apache Software
			// Foundation. JARs that ship no pom metadata fall through to the known
			// package list, whose groovy entries carry the 3.x-era group ID, so a
			// major-version migration keeps 4.x artifacts under org.apache.groovy
			// (github.com/anchore/syft/issues/5311).
			name:     "known package list groovy 4",
			pkgName:  "groovy",
			version:  "4.0.33",
			metadata: pkg.JavaArchive{},
			expect:   "org.apache.groovy",
		},
		{
			name:     "known package list groovy 4 family",
			pkgName:  "groovy-json",
			version:  "4.0.33",
			metadata: pkg.JavaArchive{},
			expect:   "org.apache.groovy",
		},
		{
			name:     "groovy bare major version migrates",
			pkgName:  "groovy",
			version:  "4",
			metadata: pkg.JavaArchive{},
			expect:   "org.apache.groovy",
		},
		{
			name:     "groovy snapshot with numeric leading major migrates",
			pkgName:  "groovy",
			version:  "4.1-SNAPSHOT",
			metadata: pkg.JavaArchive{},
			expect:   "org.apache.groovy",
		},
		{
			name:     "groovy v-prefixed version is not a maven version and keeps the historical group",
			pkgName:  "groovy",
			version:  "v4.0.33",
			metadata: pkg.JavaArchive{},
			expect:   "org.codehaus.groovy",
		},
		{
			// The Eclipse-hosted groovy-eclipse-* artifacts share the groovy prefix
			// but kept the Codehaus coordinates, so the migration must not capture
			// them even at 4.x and newer.
			name:     "groovy-eclipse artifacts keep the Codehaus group",
			pkgName:  "groovy-eclipse-batch",
			version:  "4.0.0",
			metadata: pkg.JavaArchive{},
			expect:   "org.codehaus.groovy",
		},
		{
			// The migration only applies where the static map attributes the
			// artifact to the previous group; other mapped artifacts are untouched.
			name:     "other mapped artifacts are unaffected by the migration",
			pkgName:  "spring-boot-starter-groovy-templates",
			version:  "4.0.33",
			metadata: pkg.JavaArchive{},
			expect:   "org.springframework.boot",
		},
		{
			name:     "known package list groovy 3 keeps the Codehaus group",
			pkgName:  "groovy",
			version:  "3.0.7",
			metadata: pkg.JavaArchive{},
			expect:   "org.codehaus.groovy",
		},
		{
			name:    "groovy 4 manifest without a dotted group falls through to the migration",
			pkgName: "groovy",
			version: "4.0.33",
			metadata: pkg.JavaArchive{
				Manifest: &pkg.JavaManifest{
					Main: []pkg.KeyValue{
						{Key: "Bundle-SymbolicName", Value: "groovy"},
						{Key: "Implementation-Vendor", Value: "The Apache Software Foundation"},
						{Key: "Automatic-Module-Name", Value: "org.apache.groovy"},
					},
				},
			},
			expect: "org.apache.groovy",
		},
		{
			name:     "groovy without a parseable version keeps the historical group",
			pkgName:  "groovy",
			metadata: pkg.JavaArchive{},
			expect:   "org.codehaus.groovy",
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
