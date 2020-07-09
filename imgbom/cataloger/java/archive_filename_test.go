package java

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/sergi/go-diff/diffmatchpatch"
	"testing"
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
			filename:  "pkg-extra-field-maven-4.3.2-rc1.ear",
			version:   "4.3.2-rc1",
			extension: "ear",
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
	}

	for _, test := range tests {
		t.Run(test.filename, func(t *testing.T) {
			obj := newJavaArchiveFilename(test.filename)

			version := obj.version()
			if version != test.version {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(version, test.version, true)
				t.Errorf("mismatched version:\n%s", dmp.DiffPrettyText(diffs))
			}

			extension := obj.extension()
			if extension != test.extension {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(extension, test.extension, true)
				t.Errorf("mismatched extension:\n%s", dmp.DiffPrettyText(diffs))
			}

			name := obj.name()
			if name != test.name {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(name, test.name, true)
				t.Errorf("mismatched name:\n%s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
