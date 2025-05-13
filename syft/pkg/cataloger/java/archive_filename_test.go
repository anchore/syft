package java

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/syft/syft/pkg"
)

func TestExtractInfoFromJavaArchiveFilename(t *testing.T) {
	tests := []struct {
		filename  string
		version   string
		extension string
		name      string
		ty        pkg.Type
	}{
		{
			filename:  "pkg-maven-4.3.2.blerg",
			version:   "4.3.2",
			extension: "blerg",
			name:      "pkg-maven",
			ty:        pkg.UnknownPkg,
		},
		{
			filename:  "pkg-maven.4.3.2.blerg",
			version:   "4.3.2",
			extension: "blerg",
			name:      "pkg-maven",
			ty:        pkg.UnknownPkg,
		},
		{
			filename:  "pkg-maven_4.3.2.blerg",
			version:   "4.3.2",
			extension: "blerg",
			name:      "pkg-maven",
			ty:        pkg.UnknownPkg,
		},
		{
			filename:  "pkg-maven-4.3.2.jar",
			version:   "4.3.2",
			extension: "jar",
			name:      "pkg-maven",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "pkg-extra-field-maven-4.3.2.war",
			version:   "4.3.2",
			extension: "war",
			name:      "pkg-extra-field-maven",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "liferay-package.lpkg",
			version:   "",
			extension: "lpkg",
			name:      "liferay-package",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "pkg-extra-field-maven-4.3.2-rc1.ear",
			version:   "4.3.2-rc1",
			extension: "ear",
			name:      "pkg-extra-field-maven",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "pkg-extra-field-maven-4.3.2-rc1.par",
			version:   "4.3.2-rc1",
			extension: "par",
			name:      "pkg-extra-field-maven",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "pkg-extra-field-maven-4.3.2-rc1.sar",
			version:   "4.3.2-rc1",
			extension: "sar",
			name:      "pkg-extra-field-maven",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "pkg-extra-field-maven-4.3.2-rc1.nar",
			version:   "4.3.2-rc1",
			extension: "nar",
			name:      "pkg-extra-field-maven",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "pkg-extra-field-maven-4.3.2-rc1.kar",
			version:   "4.3.2-rc1",
			extension: "kar",
			name:      "pkg-extra-field-maven",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/some/path/pkg-extra-field-maven-4.3.2-rc1.jpi",
			version:   "4.3.2-rc1",
			extension: "jpi",
			name:      "pkg-extra-field-maven",
			ty:        pkg.JenkinsPluginPkg,
		},
		{
			filename:  "/some/path-with-version-5.4.3/pkg-extra-field-maven-4.3.2-rc1.hpi",
			version:   "4.3.2-rc1",
			extension: "hpi",
			name:      "pkg-extra-field-maven",
			ty:        pkg.JenkinsPluginPkg,
		},
		{
			filename:  "/some/path-with-version-5.4.3/wagon-webdav-1.0.2-beta-2.2.3a-hudson.jar",
			version:   "1.0.2-beta-2.2.3a-hudson",
			extension: "jar",
			name:      "wagon-webdav",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/some/path-with-version-5.4.3/wagon-webdav-1.0.2-beta-2.2.3-hudson.jar",
			version:   "1.0.2-beta-2.2.3-hudson",
			extension: "jar",
			name:      "wagon-webdav",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/some/path-with-version-5.4.3/windows-remote-command-1.0.jar",
			version:   "1.0",
			extension: "jar",
			name:      "windows-remote-command",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/some/path-with-version-5.4.3/wagon-http-lightweight-1.0.5-beta-2.jar",
			version:   "1.0.5-beta-2",
			extension: "jar",
			name:      "wagon-http-lightweight",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/hudson.war:WEB-INF/lib/commons-jelly-1.1-hudson-20100305.jar",
			version:   "1.1-hudson-20100305",
			extension: "jar",
			name:      "commons-jelly",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/hudson.war:WEB-INF/lib/jtidy-4aug2000r7-dev-hudson-1.jar",
			version:   "4aug2000r7-dev-hudson-1",
			extension: "jar",
			name:      "jtidy",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/hudson.war:WEB-INF/lib/trilead-ssh2-build212-hudson-5.jar",
			version:   "build212-hudson-5",
			extension: "jar",
			name:      "trilead-ssh2",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/hudson.war:WEB-INF/lib/guava-r06.jar",
			version:   "r06",
			extension: "jar",
			name:      "guava",
			ty:        pkg.JavaPkg,
		},
		{
			// regression: https://github.com/anchore/syft/issues/255
			filename:  "BOOT-INF/lib/spring-data-r2dbc-1.1.0.RELEASE.jar",
			version:   "1.1.0.RELEASE",
			extension: "jar",
			name:      "spring-data-r2dbc",
			ty:        pkg.JavaPkg,
		},
		{
			// regression for artifact of the same name within jboss/keycloak:13.0.1 docker image
			// which covers package name components with periods in them
			filename:  "jboss-saaj-api_1.4_spec-1.0.2.Final.jar",
			version:   "1.0.2.Final",
			extension: "jar",
			name:      "jboss-saaj-api_1.4_spec",
			ty:        pkg.JavaPkg,
		},
		{
			filename:  "/usr/share/java/gradle/lib/gradle-build-cache-8.1.1.jar",
			version:   "8.1.1",
			extension: "jar",
			name:      "gradle-build-cache",
			ty:        pkg.JavaPkg,
		},
	}

	for _, test := range tests {
		t.Run(test.filename, func(t *testing.T) {
			obj := newJavaArchiveFilename(test.filename)

			ty := obj.pkgType()
			if ty != test.ty {
				t.Errorf("mismatched type: %+v != %v", ty, test.ty)
			}

			version := obj.version
			if version != test.version {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.version, version, true)
				t.Errorf("mismatched version:\n%s", dmp.DiffPrettyText(diffs))
			}

			extension := obj.extension()
			if extension != test.extension {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.extension, extension, true)
				t.Errorf("mismatched extension:\n%s", dmp.DiffPrettyText(diffs))
			}

			name := obj.name
			if name != test.name {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.name, name, true)
				t.Errorf("mismatched name:\n%s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
