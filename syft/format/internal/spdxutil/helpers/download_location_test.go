package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_DownloadLocation(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: NOASSERTION,
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					URL: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "",
				},
			},
			expected: NOASSERTION,
		},
		{
			name: "from npm package-lock should include resolved",
			input: pkg.Package{
				Metadata: pkg.NpmPackageLockEntry{
					Resolved: "http://package-lock.test",
				},
			},
			expected: "http://package-lock.test",
		},
		{
			name: "from npm package-lock empty should be NONE",
			input: pkg.Package{
				Metadata: pkg.NpmPackageLockEntry{
					Resolved: "",
				},
			},
			expected: NOASSERTION,
		},
		{
			name: "from php installed.json",
			input: pkg.Package{
				Metadata: pkg.PhpComposerInstalledEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "http://package-lock.test",
					},
				},
			},
			expected: "http://package-lock.test",
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.PhpComposerInstalledEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "",
					},
				},
			},
			expected: NOASSERTION,
		},
		{
			name: "from php composer.lock",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "http://package-lock.test",
					},
				},
			},
			expected: "http://package-lock.test",
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "",
					},
				},
			},
			expected: NOASSERTION,
		},
		{
			name: "none",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "none",
					},
				},
			},
			expected: NONE,
		},
		{
			name: "none uppercase",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "NONE",
					},
				},
			},
			expected: NONE,
		},
		{
			name: "invalid uri",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "example/package",
					},
				},
			},
			expected: NOASSERTION,
		},
		{
			name: "Basic Git Protocol URL",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git://git.myproject.org/MyProject",
					},
				},
			},
			expected: "git://git.myproject.org/MyProject",
		},
		{
			name: "Git HTTPS URL with .git Extension",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git+https://git.myproject.org/MyProject.git",
					},
				},
			},
			expected: "git+https://git.myproject.org/MyProject.git",
		},
		{
			name: "Git HTTP URL",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git+http://git.myproject.org/MyProject",
					},
				},
			},
			expected: "git+http://git.myproject.org/MyProject",
		},
		{
			name: "Git SSH URL with .git Extension",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git+ssh://git.myproject.org/MyProject.git",
					},
				},
			},
			expected: "git+ssh://git.myproject.org/MyProject.git",
		},
		{
			name: "Git Protocol with Prefix",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git+git://git.myproject.org/MyProject",
					},
				},
			},
			expected: "git+git://git.myproject.org/MyProject",
		},
		{
			name: "Git URL with C File Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git://git.myproject.org/MyProject#src/somefile.c",
					},
				},
			},
			expected: "git://git.myproject.org/MyProject#src/somefile.c",
		},
		{
			name: "Git HTTPS URL with Java File Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git+https://git.myproject.org/MyProject#src/Class.java",
					},
				},
			},
			expected: "git+https://git.myproject.org/MyProject#src/Class.java",
		},
		{
			name: "Git URL with Master Branch",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git://git.myproject.org/MyProject.git@master",
					},
				},
			},
			expected: "git://git.myproject.org/MyProject.git@master",
		},
		{
			name: "Git HTTPS URL with Version Tag",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git+https://git.myproject.org/MyProject.git@v1.0",
					},
				},
			},
			expected: "git+https://git.myproject.org/MyProject.git@v1.0",
		},
		{
			name: "Git URL with Full Commit Hash",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git://git.myproject.org/MyProject.git@da39a3ee5e6b4b0d3255bfef95601890afd80709",
					},
				},
			},
			expected: "git://git.myproject.org/MyProject.git@da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			name: "Git HTTPS URL with Branch and CPP File Path",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git+https://git.myproject.org/MyProject.git@master#/src/MyClass.cpp",
					},
				},
			},
			expected: "git+https://git.myproject.org/MyProject.git@master#/src/MyClass.cpp",
		},
		{
			name: "Git HTTPS URL with Commit Hash and Ruby File",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "git+https://git.myproject.org/MyProject@da39a3ee5e6b4b0d3255bfef95601890afd80709#lib/variable.rb",
					},
				},
			},
			expected: "git+https://git.myproject.org/MyProject@da39a3ee5e6b4b0d3255bfef95601890afd80709#lib/variable.rb",
		},
		{
			name: "Basic Mercurial HTTP URL",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+http://hg.myproject.org/MyProject",
					},
				},
			},
			expected: "hg+http://hg.myproject.org/MyProject",
		},
		{
			name: "Basic Mercurial HTTPS URL",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject",
		},
		{
			name: "Basic Mercurial SSH URL",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+ssh://hg.myproject.org/MyProject",
					},
				},
			},
			expected: "hg+ssh://hg.myproject.org/MyProject",
		},
		{
			name: "Mercurial URL with File Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject#src/somefile.c",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject#src/somefile.c",
		},
		{
			name: "Mercurial URL with Java Class Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject#src/Class.java",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject#src/Class.java",
		},
		{
			name: "Mercurial URL with Commit Hash",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject@da39a3ee5e6b",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject@da39a3ee5e6b",
		},
		{
			name: "Mercurial URL with Year Reference",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject@2019",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject@2019",
		},
		{
			name: "Mercurial URL with Version Tag",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject@v1.0",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject@v1.0",
		},
		{
			name: "Mercurial URL with Feature Branch",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject@special_feature",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject@special_feature",
		},
		{
			name: "Mercurial URL with Branch and File Path",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject@master#/src/MyClass.cpp",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject@master#/src/MyClass.cpp",
		},
		{
			name: "Mercurial URL with Commit Hash and Ruby File",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "hg+https://hg.myproject.org/MyProject@da39a3ee5e6b#lib/variable.rb",
					},
				},
			},
			expected: "hg+https://hg.myproject.org/MyProject@da39a3ee5e6b#lib/variable.rb",
		},

		// Test cases for Subversion (svn) URLs
		{
			name: "Basic SVN URL",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn://svn.myproject.org/svn/MyProject",
					},
				},
			},
			expected: "svn://svn.myproject.org/svn/MyProject",
		},
		{
			name: "SVN URL with Protocol Prefix",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+svn://svn.myproject.org/svn/MyProject",
					},
				},
			},
			expected: "svn+svn://svn.myproject.org/svn/MyProject",
		},
		{
			name: "SVN HTTP URL with Trunk",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+http://svn.myproject.org/svn/MyProject/trunk",
					},
				},
			},
			expected: "svn+http://svn.myproject.org/svn/MyProject/trunk",
		},
		{
			name: "SVN HTTPS URL with Trunk",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+https://svn.myproject.org/svn/MyProject/trunk",
					},
				},
			},
			expected: "svn+https://svn.myproject.org/svn/MyProject/trunk",
		},
		{
			name: "SVN URL with C File Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+https://svn.myproject.org/MyProject#src/somefile.c",
					},
				},
			},
			expected: "svn+https://svn.myproject.org/MyProject#src/somefile.c",
		},
		{
			name: "SVN URL with Java Class Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+https://svn.myproject.org/MyProject#src/Class.java",
					},
				},
			},
			expected: "svn+https://svn.myproject.org/MyProject#src/Class.java",
		},
		{
			name: "SVN URL with Trunk and C File Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+https://svn.myproject.org/MyProject/trunk#src/somefile.c",
					},
				},
			},
			expected: "svn+https://svn.myproject.org/MyProject/trunk#src/somefile.c",
		},
		{
			name: "SVN URL with Full File Path",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+https://svn.myproject.org/MyProject/trunk/src/somefile.c",
					},
				},
			},
			expected: "svn+https://svn.myproject.org/MyProject/trunk/src/somefile.c",
		},
		{
			name: "SVN URL with Revision Number",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+https://svn.myproject.org/svn/MyProject/trunk@2019",
					},
				},
			},
			expected: "svn+https://svn.myproject.org/svn/MyProject/trunk@2019",
		},
		{
			name: "SVN URL with Revision and CPP File Path",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+https://svn.myproject.org/MyProject@123#/src/MyClass.cpp",
					},
				},
			},
			expected: "svn+https://svn.myproject.org/MyProject@123#/src/MyClass.cpp",
		},
		{
			name: "SVN URL with Trunk, Revision and Ruby File Path",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "svn+https://svn.myproject.org/MyProject/trunk@1234#lib/variable/variable.rb",
					},
				},
			},
			expected: "svn+https://svn.myproject.org/MyProject/trunk@1234#lib/variable/variable.rb",
		},

		// Test cases for Bazaar (bzr) URLs
		{
			name: "Bazaar HTTPS URL with Trunk",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+https://bzr.myproject.org/MyProject/trunk",
					},
				},
			},
			expected: "bzr+https://bzr.myproject.org/MyProject/trunk",
		},
		{
			name: "Bazaar HTTP URL with Trunk",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+http://bzr.myproject.org/MyProject/trunk",
					},
				},
			},
			expected: "bzr+http://bzr.myproject.org/MyProject/trunk",
		},
		{
			name: "Bazaar SFTP URL with Trunk",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+sftp://myproject.org/MyProject/trunk",
					},
				},
			},
			expected: "bzr+sftp://myproject.org/MyProject/trunk",
		},
		{
			name: "Bazaar SSH URL with Trunk",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+ssh://myproject.org/MyProject/trunk",
					},
				},
			},
			expected: "bzr+ssh://myproject.org/MyProject/trunk",
		},
		{
			name: "Bazaar FTP URL with Trunk",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+ftp://myproject.org/MyProject/trunk",
					},
				},
			},
			expected: "bzr+ftp://myproject.org/MyProject/trunk",
		},
		{
			name: "Bazaar Launchpad URL",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+lp:MyProject",
					},
				},
			},
			expected: "bzr+lp:MyProject",
		},
		{
			name: "Bazaar URL with C File Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+https://bzr.myproject.org/MyProject/trunk#src/somefile.c",
					},
				},
			},
			expected: "bzr+https://bzr.myproject.org/MyProject/trunk#src/somefile.c",
		},
		{
			name: "Bazaar URL with Java Class Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+https://bzr.myproject.org/MyProject/trunk#src/Class.java",
					},
				},
			},
			expected: "bzr+https://bzr.myproject.org/MyProject/trunk#src/Class.java",
		},
		{
			name: "Bazaar URL with Revision",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+https://bzr.myproject.org/MyProject/trunk@2019",
					},
				},
			},
			expected: "bzr+https://bzr.myproject.org/MyProject/trunk@2019",
		},
		{
			name: "Bazaar URL with Version Tag",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+http://bzr.myproject.org/MyProject/trunk@v1.0",
					},
				},
			},
			expected: "bzr+http://bzr.myproject.org/MyProject/trunk@v1.0",
		},
		{
			name: "Bazaar URL with Revision and C File Fragment",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Dist: pkg.PhpComposerExternalReference{
						URL: "bzr+https://bzr.myproject.org/MyProject/trunk@2019#src/somefile.c",
					},
				},
			},
			expected: "bzr+https://bzr.myproject.org/MyProject/trunk@2019#src/somefile.c",
		},

		{
			name: "Github Repository",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					URL: "github:anchore/syft",
				},
			},
			expected: "https://github.com/anchore/syft",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, DownloadLocation(test.input))
		})
	}
}
