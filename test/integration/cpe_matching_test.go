package integration

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/scylladb/go-set"
	"github.com/scylladb/go-set/strset"
	"sort"
	"testing"
)

func TestIdentifyPackages(t *testing.T) {
	tests := []struct {
		name     string
		fixture  pkg.Package
		expected []string
	}{
		{
			name: "Google Guava",
			fixture: pkg.Package{
				Name:         "guava",
				Version:      "30.1",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "guava",
						GroupID:    "com.google.guava",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:google:guava:30.1:*:*:*:*:java:*:*",
			},
		},
		{
			name: "Spring Boot (Specific Vendor & product)",
			fixture: pkg.Package{
				Name:         "spring-boot",
				Version:      "2.4.2",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "spring-boot",
						GroupID:    "org.springframework.boot",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:pivotal_software:spring_boot:2.4.2:*:*:*:*:java:*:*",
			},
		},
		{
			name: "Joda Time (no match)",
			fixture: pkg.Package{
				Name:         "joda-time",
				Version:      "2.10.9",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						Main: map[string]string{
							"Implementation-Vendor":    "Joda.org",
							"Implementation-Vendor-Id": "org.joda",
						},
					},
					PomProperties: &pkg.PomProperties{
						ArtifactID: "joda-time",
						GroupID:    "joda-time",
					},
				},
			},
			expected: []string{},
		},
		{
			name: "Tomcat Embedded",
			fixture: pkg.Package{
				Name:         "tomcat-embed-core",
				Version:      "10.0.0",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						Main: map[string]string{
							"Implementation-Vendor": "Apache Software Foundation",
							"Implementation-Title":  "Apache Tomcat",
						},
					},
					PomProperties: &pkg.PomProperties{
						ArtifactID: "tomcat-embed-core",
						GroupID:    "org.apache.tomcat.embed",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:apache_software_foundation:tomcat:10.0.0:*:*:*:*:java:*:*",
			},
		},
		{
			name: "Jackson XML",
			fixture: pkg.Package{
				Name:         "jackson-core",
				Version:      "10.0.0",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						Main: map[string]string{
							"Implementation-Vendor": "FasterXML",
						},
					},
					PomProperties: &pkg.PomProperties{
						ArtifactID: "jackson-core",
						GroupID:    "com.fasterxml.jackson.core",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:fasterxml:jackson:10.0.0:*:*:*:*:java:*:*",
			},
		},
		{
			name: "Snakeyaml (ignore package in name)",
			fixture: pkg.Package{
				Name:         "snakeyaml",
				Version:      "1.27",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "snakeyaml",
						GroupID:    "org.yaml",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:snakeyaml_project:snakeyaml:1.27:*:*:*:*:java:*:*",
			},
		},
	}

	cacheDir, _ := ioutils.TempDir("", "cpe_dictionary_update_test")
	cpeDictionaryConfig := config.CPEDictionary{
		CacheDir:         cacheDir,
		UpdateURL:        "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz",
		AutoUpdate:       true,
		ValidateChecksum: false,
		MinimumScore:     4,
		SpecificVendors: []config.SpecificMatch{
			{"^spring-.*$", "pivotal_software", 4},
		},
		SpecificProducts: []config.SpecificMatch{
			{"^spring-boot.*$", "boot", 4},
			{"^spring-.*$", "framework", 4},
		},
	}
	curator := cpe.NewCurator(cpeDictionaryConfig)
	defer curator.Delete()

	result, err := curator.Update()
	if err != nil && result != false {
		t.Fatalf("failed to update CPE dictionary: %+v", err)
	}

	dictionary, _ := curator.GetDictionary()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := dictionary.IdentifyPackageCPEs(test.fixture)

			expectedCpeSet := set.NewStringSet(test.expected...)
			actualCpeSet := set.NewStringSet()
			for _, a := range actual {
				actualCpeSet.Add(a.BindToFmtString())
			}

			extra := strset.Difference(expectedCpeSet, actualCpeSet).List()
			sort.Strings(extra)
			for _, d := range extra {
				t.Errorf("  extra CPE: %+v", d)
			}

			missing := strset.Difference(actualCpeSet, expectedCpeSet).List()
			sort.Strings(missing)
			for _, d := range missing {
				t.Errorf("  missing CPE: %+v", d)
			}
		})
	}

}
