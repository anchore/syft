package java

import (
	"testing"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_ArchiveCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain java archive files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"java-archives/example.jar",
				"java-archives/example.war",
				"java-archives/example.ear",
				"java-archives/example.par",
				"java-archives/example.sar",
				"java-archives/example.nar",
				"java-archives/example.kar",
				"java-archives/example.jpi",
				"java-archives/example.hpi",
				"java-archives/example.lpkg",
				"archives/example.zip",
				"archives/example.tar",
				"archives/example.tar.gz",
				"archives/example.tgz",
				"archives/example.tar.bz",
				"archives/example.tar.bz2",
				"archives/example.tbz",
				"archives/example.tbz2",
				"archives/example.tar.br",
				"archives/example.tbr",
				"archives/example.tar.lz4",
				"archives/example.tlz4",
				"archives/example.tar.sz",
				"archives/example.tsz",
				"archives/example.tar.xz",
				"archives/example.txz",
				"archives/example.tar.zst",
				"archives/example.tzst",
				"archives/example.tar.zstd",
				"archives/example.tzstd",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t,
					NewArchiveCataloger(
						ArchiveCatalogerConfig{
							ArchiveSearchConfig: cataloging.ArchiveSearchConfig{
								IncludeIndexedArchives:   true,
								IncludeUnindexedArchives: true,
							},
						},
					),
				)
		})
	}
}

func Test_POMCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain java pom files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/pom.xml",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t,
					NewPomCataloger(
						ArchiveCatalogerConfig{
							ArchiveSearchConfig: cataloging.ArchiveSearchConfig{
								IncludeIndexedArchives:   true,
								IncludeUnindexedArchives: true,
							},
						},
					))
		})
	}
}

func TestJvmDistributionCataloger(t *testing.T) {

	cases := []struct {
		name     string
		fixture  string
		expected pkg.Package
	}{
		{
			name:    "valid 1.8.0",
			fixture: "test-fixtures/jvm-installs/oracle-jdk-se-8",
			expected: pkg.Package{
				Name:      "jdk",
				Version:   "1.8.0_411-b25",
				FoundBy:   "java-jvm-cataloger",
				Locations: file.NewLocationSet(file.NewLocation("usr/lib/jvm/jdk-1.8-oracle-x64/release")),
				Licenses:  pkg.NewLicenseSet(),
				Type:      pkg.BinaryPkg,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:oracle:java_se:1.8.0:update411:*:*:*:*:*:*", cpe.DeclaredSource),
					cpe.Must("cpe:2.3:a:oracle:jre:1.8.0:update411:*:*:*:*:*:*", cpe.DeclaredSource),
					cpe.Must("cpe:2.3:a:oracle:jdk:1.8.0:update411:*:*:*:*:*:*", cpe.DeclaredSource),
				},
				PURL: "pkg:generic/oracle/jdk@1.8.0_411-b25",
				Metadata: pkg.JavaVMInstallation{
					Release: pkg.JavaVMRelease{
						JavaRuntimeVersion: "1.8.0_411-b25",
						JavaVersion:        "1.8.0_411",
						OsArch:             "amd64",
						OsName:             "Linux",
						OsVersion:          "2.6",
						Source:             ".:git:71ec2089cf8c+",
						BuildType:          "commercial",
					},
					Files: []string{
						"usr/lib/jvm/jdk-1.8-oracle-x64/bin/javac",
						"usr/lib/jvm/jdk-1.8-oracle-x64/release",
					},
				},
			},
		},
		{
			name:    "valid post-jep223",
			fixture: "test-fixtures/jvm-installs/valid-post-jep223",
			expected: pkg.Package{
				Name:      "openjdk",
				Version:   "21.0.4+7-LTS",
				FoundBy:   "java-jvm-cataloger",
				Locations: file.NewLocationSet(file.NewLocation("jvm/openjdk/release")),
				Licenses:  pkg.NewLicenseSet(),
				Type:      pkg.BinaryPkg,
				CPEs:      []cpe.CPE{cpe.Must("cpe:2.3:a:oracle:openjdk:21.0.4:*:*:*:*:*:*:*", cpe.DeclaredSource)},
				PURL:      "pkg:generic/oracle/openjdk@21.0.4%2B7-LTS?repository_url=https://github.com/adoptium/jdk21u.git",
				Metadata: pkg.JavaVMInstallation{
					Release: pkg.JavaVMRelease{
						Implementor:        "Eclipse Adoptium",
						ImplementorVersion: "Temurin-21.0.4+7",
						JavaRuntimeVersion: "21.0.4+7-LTS",
						JavaVersion:        "21.0.4",
						JavaVersionDate:    "2024-07-16",
						Libc:               "gnu",
						Modules: []string{
							"java.base", "java.compiler", "java.datatransfer", "java.xml", "java.prefs",
							"java.desktop", "java.instrument", "java.logging", "java.management",
							"java.security.sasl", "java.naming", "java.rmi", "java.management.rmi",
							"java.net.http", "java.scripting", "java.security.jgss",
							"java.transaction.xa", "java.sql", "java.sql.rowset", "java.xml.crypto", "java.se",
							"java.smartcardio", "jdk.accessibility", "jdk.internal.jvmstat", "jdk.attach",
							"jdk.charsets", "jdk.internal.opt", "jdk.zipfs", "jdk.compiler", "jdk.crypto.ec",
							"jdk.crypto.cryptoki", "jdk.dynalink", "jdk.internal.ed", "jdk.editpad", "jdk.hotspot.agent",
							"jdk.httpserver", "jdk.incubator.vector", "jdk.internal.le", "jdk.internal.vm.ci",
							"jdk.internal.vm.compiler", "jdk.internal.vm.compiler.management", "jdk.jartool",
							"jdk.javadoc", "jdk.jcmd", "jdk.management", "jdk.management.agent", "jdk.jconsole",
							"jdk.jdeps", "jdk.jdwp.agent", "jdk.jdi", "jdk.jfr", "jdk.jlink", "jdk.jpackage", "jdk.jshell",
							"jdk.jsobject", "jdk.jstatd", "jdk.localedata", "jdk.management.jfr", "jdk.naming.dns",
							"jdk.naming.rmi", "jdk.net", "jdk.nio.mapmode", "jdk.random", "jdk.sctp", "jdk.security.auth",
							"jdk.security.jgss", "jdk.unsupported", "jdk.unsupported.desktop", "jdk.xml.dom",
						},
						OsArch:          "aarch64",
						OsName:          "Linux",
						Source:          ".:git:13710926b798",
						BuildSource:     "git:1271f10a26c47e1489a814dd2731f936a588d621",
						BuildSourceRepo: "https://github.com/adoptium/temurin-build.git",
						SourceRepo:      "https://github.com/adoptium/jdk21u.git",
						FullVersion:     "21.0.4+7-LTS",
						SemanticVersion: "21.0.4+7",
						BuildInfo:       "OS: Linux Version: 5.4.0-150-generic",
						JvmVariant:      "Hotspot",
						JvmVersion:      "21.0.4+7-LTS",
						ImageType:       "JDK",
					},
					Files: []string{
						"jvm/openjdk/release",
						"jvm/openjdk/sibling/child/file1.txt",
					},
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.expected
			p.SetID()

			pkgtest.TestCataloger(t, tt.fixture, NewJvmDistributionCataloger(), []pkg.Package{p}, nil)
		})
	}

}
