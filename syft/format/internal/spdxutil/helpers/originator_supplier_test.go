package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/pkg"
)

func Test_OriginatorSupplier(t *testing.T) {
	completionTester := packagemetadata.NewCompletionTester(t,
		pkg.BinarySignature{},
		pkg.CocoaPodfileLockEntry{},
		pkg.ConanV1LockEntry{},
		pkg.ConanV2LockEntry{}, // the field Username might be the username of either the package originator or the supplier (unclear currently)
		pkg.ConanfileEntry{},
		pkg.ConaninfoEntry{},
		pkg.DartPubspecLockEntry{},
		pkg.DotnetDepsEntry{},
		pkg.ELFBinaryPackageNoteJSONPayload{},
		pkg.ElixirMixLockEntry{},
		pkg.ErlangRebarLockEntry{},
		pkg.GolangBinaryBuildinfoEntry{},
		pkg.GolangModuleEntry{},
		pkg.HackageStackYamlLockEntry{},
		pkg.HackageStackYamlEntry{},
		pkg.LinuxKernel{},
		pkg.LuaRocksPackage{},
		pkg.MicrosoftKbPatch{},
		pkg.NixStoreEntry{},
		pkg.NpmPackageLockEntry{},
		pkg.PhpComposerInstalledEntry{},
		pkg.PhpPeclEntry{},
		pkg.PortageEntry{},
		pkg.PythonPipfileLockEntry{},
		pkg.PythonRequirementsEntry{},
		pkg.PythonPoetryLockEntry{},
		pkg.RustBinaryAuditEntry{},
		pkg.RustCargoLockEntry{},
		pkg.SwiftPackageManagerResolvedEntry{},
		pkg.SwiplPackEntry{},
		pkg.OpamPackage{},
		pkg.YarnLockEntry{},
	)
	tests := []struct {
		name       string
		input      pkg.Package
		originator string
		supplier   string
	}{
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name:       "no metadata",
			input:      pkg.Package{},
			originator: "",
			supplier:   "",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty author on existing metadata",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Author: "",
				},
			},
			originator: "",
			supplier:   "",
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkDBEntry{
					Maintainer: "auth",
				},
			},
			originator: "Person: auth",
			supplier:   "Person: auth",
		},
		{
			name: "from alpm",
			input: pkg.Package{
				Metadata: pkg.AlpmDBEntry{
					Packager: "someone",
				},
			},
			originator: "",
			supplier:   "Person: someone",
		},
		{
			name: "from dotnet -- PE binary",
			input: pkg.Package{
				Metadata: pkg.DotnetPortableExecutableEntry{
					CompanyName: "Microsoft Corporation",
				},
			},
			originator: "Organization: Microsoft Corporation",
			supplier:   "Organization: Microsoft Corporation",
		},
		{
			name: "from dpkg",
			input: pkg.Package{
				Metadata: pkg.DpkgDBEntry{
					Maintainer: "auth",
				},
			},
			originator: "Person: auth",
			supplier:   "Person: auth",
		},
		{
			name: "from gem",
			input: pkg.Package{
				Metadata: pkg.RubyGemspec{
					Authors: []string{
						"auth1",
						"auth2",
					},
				},
			},
			originator: "Person: auth1",
			supplier:   "Person: auth1",
		},
		{
			name: "from java -- spec > impl cendor in main manifest section",
			input: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: pkg.KeyValues{
							{
								Key:   "Implementation-Vendor",
								Value: "auth-impl",
							},
							{
								Key:   "Specification-Vendor",
								Value: "auth-spec",
							},
						},
					},
				},
			},
			originator: "Organization: auth-spec",
			supplier:   "Organization: auth-spec",
		},
		{
			name: "from java -- fallback to impl vendor in main manifest section",
			input: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Main: pkg.KeyValues{
							{
								Key:   "Implementation-Vendor",
								Value: "auth-impl",
							},
						},
					},
				},
			},
			originator: "Organization: auth-impl",
			supplier:   "Organization: auth-impl",
		},
		{
			name: "from java -- non-main manifest sections ignored",
			input: pkg.Package{
				Metadata: pkg.JavaArchive{
					Manifest: &pkg.JavaManifest{
						Sections: []pkg.KeyValues{
							{
								{
									Key:   "Implementation-Vendor",
									Value: "auth-impl",
								},
							},
						},
						Main: pkg.KeyValues{},
					},
				},
			},
			// note: empty!
		},
		{
			name: "from java -- jvm installation",
			input: pkg.Package{
				Metadata: pkg.JavaVMInstallation{
					Release: pkg.JavaVMRelease{
						Implementor: "Oracle",
					},
				},
			},
			originator: "Organization: Oracle",
			supplier:   "Organization: Oracle",
		},
		{
			name: "from linux kernel module",
			input: pkg.Package{
				Metadata: pkg.LinuxKernelModule{
					Author: "auth",
				},
			},
			originator: "Person: auth",
			supplier:   "Person: auth",
		},
		{
			name: "from Lua Rockspecs",
			input: pkg.Package{
				Metadata: pkg.LuaRocksPackage{},
			},
			originator: "",
			supplier:   "",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Author: "auth",
				},
			},
			originator: "Person: auth",
			supplier:   "Person: auth",
		},
		{
			name: "from npm -- name, email, and url",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Author: "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
				},
			},
			originator: "Person: Isaac Z. Schlueter (i@izs.me)",
			supplier:   "Person: Isaac Z. Schlueter (i@izs.me)",
		},
		{
			name: "from npm -- name, email",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Author: "Isaac Z. Schlueter <i@izs.me>",
				},
			},
			originator: "Person: Isaac Z. Schlueter (i@izs.me)",
			supplier:   "Person: Isaac Z. Schlueter (i@izs.me)",
		},
		{
			name: "from php composer installed file",
			input: pkg.Package{
				Metadata: pkg.PhpComposerInstalledEntry{
					Authors: []pkg.PhpComposerAuthors{
						{
							Name:  "auth",
							Email: "me@auth.com",
						},
					},
				},
			},
			originator: "Person: auth (me@auth.com)",
			supplier:   "Person: auth (me@auth.com)",
		},
		{
			name: "from php composer installed file",
			input: pkg.Package{
				Metadata: pkg.PhpComposerLockEntry{
					Authors: []pkg.PhpComposerAuthors{
						{
							Name:  "auth",
							Email: "me@auth.com",
						},
					},
				},
			},
			originator: "Person: auth (me@auth.com)",
			supplier:   "Person: auth (me@auth.com)",
		},
		{
			name: "from python - just name",
			input: pkg.Package{
				Metadata: pkg.PythonPackage{
					Author: "auth",
				},
			},
			originator: "Person: auth",
			supplier:   "Person: auth",
		},
		{
			name: "from python - just email",
			input: pkg.Package{
				Metadata: pkg.PythonPackage{
					AuthorEmail: "auth@auth.gov",
				},
			},
			originator: "Person: auth@auth.gov",
			supplier:   "Person: auth@auth.gov",
		},
		{
			name: "from python - both name and email",
			input: pkg.Package{
				Metadata: pkg.PythonPackage{
					Author:      "auth",
					AuthorEmail: "auth@auth.gov",
				},
			},
			originator: "Person: auth (auth@auth.gov)",
			supplier:   "Person: auth (auth@auth.gov)",
		},
		{
			name: "from r -- maintainer > author",
			input: pkg.Package{
				Metadata: pkg.RDescription{
					Author:     "author",
					Maintainer: "maintainer",
				},
			},
			originator: "Person: maintainer",
			supplier:   "Person: maintainer",
		},
		{
			name: "from r -- fallback to author",
			input: pkg.Package{
				Metadata: pkg.RDescription{
					Author: "author",
				},
			},
			originator: "Person: author",
			supplier:   "Person: author",
		},
		{
			name: "from rpm archive",
			input: pkg.Package{
				Metadata: pkg.RpmArchive{
					Vendor: "auth",
				},
			},
			originator: "Organization: auth",
			supplier:   "Organization: auth",
		},
		{
			name: "from rpm DB",
			input: pkg.Package{
				Metadata: pkg.RpmDBEntry{
					Vendor: "auth",
				},
			},
			originator: "Organization: auth",
			supplier:   "Organization: auth",
		},
		{
			name: "from wordpress plugin",
			input: pkg.Package{
				Metadata: pkg.WordpressPluginEntry{
					Author: "auth",
				},
			},
			originator: "Organization: auth",
			supplier:   "Organization: auth",
		},
		{
			name: "from swipl pack",
			input: pkg.Package{
				Metadata: pkg.SwiplPackEntry{
					Author:        "auth",
					AuthorEmail:   "auth@auth.gov",
					Packager:      "me",
					PackagerEmail: "me@auth.com",
				},
			},
			originator: "Person: auth (auth@auth.gov)",
			supplier:   "Person: me (me@auth.com)",
		},
		{
			name: "from ocaml opam",
			input: pkg.Package{
				Metadata: pkg.OpamPackage{},
			},
			originator: "",
			supplier:   "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			completionTester.Tested(t, test.input.Metadata)

			typ, value := Originator(test.input)
			if typ != "" {
				value = typ + ": " + value
			}
			assert.Equal(t, test.originator, value)

			typ, value = Supplier(test.input)
			if typ != "" {
				value = typ + ": " + value
			}
			assert.Equal(t, test.supplier, value)
		})
	}
}

func Test_parseNameEmailUrl(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantName  string
		wantEmail string
		wantUrl   string
	}{
		{
			name:  "empty",
			input: "",
		},
		{
			name:     "npm-like: name only",
			input:    "Isaac Z. Schlueter",
			wantName: "Isaac Z. Schlueter",
		},
		{
			name:      "npm-like: name and email",
			input:     "Ray Nos <bogus2@gmail.com>",
			wantName:  "Ray Nos",
			wantEmail: "bogus2@gmail.com",
		},
		{
			name:     "npm-like: name and url",
			input:    "Ray Nos (http://example.com)",
			wantName: "Ray Nos",
			wantUrl:  "http://example.com",
		},
		{
			name:      "npm-like: name, email, and url",
			input:     "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
			wantName:  "Isaac Z. Schlueter",
			wantEmail: "i@izs.me",
			wantUrl:   "http://blog.izs.me",
		},
		{
			name:      "mixed input: email only",
			input:     "i@izs.me",
			wantEmail: "i@izs.me",
		},
		{
			name:      "mixed input: email in url",
			input:     "my name (i@izs.me)",
			wantName:  "my name",
			wantEmail: "i@izs.me",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotEmail, gotUrl := parseNameEmailURL(tt.input)
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantEmail, gotEmail)
			assert.Equal(t, tt.wantUrl, gotUrl)
		})
	}
}

func Test_formatPersonOrOrg(t *testing.T) {

	tests := []struct {
		name  string
		input string
		email string
		want  string
	}{
		{
			name: "empty",
			want: "",
		},
		{
			name:  "name only",
			input: "Isaac Z. Schlueter",
			want:  "Isaac Z. Schlueter",
		},
		{
			name:  "email only",
			email: "i@something.com",
			want:  "i@something.com",
		},
		{
			name:  "name and email",
			input: "Isaac Z. Schlueter",
			email: "i@something.com",
			want:  "Isaac Z. Schlueter (i@something.com)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatPersonOrOrg(tt.input, tt.email))
		})
	}
}

func Test_approximatesAsEmail(t *testing.T) {

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "empty",
			input: "",
			want:  false,
		},
		{
			name:  "no at",
			input: "something.com",
			want:  false,
		},
		{
			name:  "no dot",
			input: "something@com",
			want:  false,
		},
		{
			name:  "dot before at",
			input: "something.com@nothing",
			want:  false,
		},
		{
			name:  "valid",
			input: "something@nothing.com",
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, approximatesAsEmail(tt.input))
		})
	}
}
