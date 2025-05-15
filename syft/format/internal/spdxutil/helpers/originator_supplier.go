package helpers

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

const (
	orgType    = "Organization"
	personType = "Person"
)

// Originator needs to conform to the SPDX spec here:
// https://spdx.github.io/spdx-spec/v2.2.2/package-information/#76-package-originator-field
//
// Definition:
//
//	If the package identified in the SPDX document originated from a different person or
//	organization than identified as Package Supplier (see 7.5 above), this field identifies from
//	where or whom the package originally came. In some cases, a package may be created and
//	originally distributed by a different third party than the Package Supplier of the package.
//	For example, the SPDX document identifies the package as glibc and the Package Supplier as
//	Red Hat, but the Free Software Foundation is the Package Originator.
//
// Use NOASSERTION if:
//
//   - the SPDX document creator has attempted to but cannot reach a reasonable objective determination;
//   - the SPDX document creator has made no attempt to determine this field; or
//   - the SPDX document creator has intentionally provided no information (no meaning should be implied by doing so).
//
// Available options are: <omit>, NOASSERTION, Person: <person>, Organization: <org>
// return values are: <type>, <value>
func Originator(p pkg.Package) (typ string, author string) { //nolint: gocyclo,funlen
	if !hasMetadata(p) {
		return typ, author
	}

	switch metadata := p.Metadata.(type) {
	case pkg.ApkDBEntry:
		author = metadata.Maintainer

	case pkg.BitnamiSBOMEntry:
		typ = orgType
		author = "Bitnami"

	case pkg.DotnetPortableExecutableEntry:
		typ = orgType
		author = metadata.CompanyName

	case pkg.DpkgDBEntry:
		author = metadata.Maintainer

	case pkg.DpkgArchiveEntry:
		author = metadata.Maintainer

	case pkg.GitHubActionsUseStatement:
		typ = orgType
		org := strings.Split(metadata.Value, "/")[0]
		if org == "actions" {
			// this is a GitHub action, so the org is GitHub
			org = "GitHub"
		}
		author = org

	case pkg.JavaArchive:
		if metadata.Manifest != nil {
			author = metadata.Manifest.Main.MustGet("Specification-Vendor")
			if author == "" {
				author = metadata.Manifest.Main.MustGet("Implementation-Vendor")
			}
			// Vendor is specified, hence set 'Organization' as the PackageSupplier
			if author != "" {
				typ = orgType
			}
		}

	case pkg.JavaVMInstallation:
		typ = orgType
		author = metadata.Release.Implementor

	case pkg.LinuxKernelModule:
		author = metadata.Author

	case pkg.PhpComposerLockEntry:
		if len(metadata.Authors) > 0 {
			entry := metadata.Authors[0]
			author = formatPersonOrOrg(entry.Name, entry.Email)
		}

	case pkg.PhpComposerInstalledEntry:
		if len(metadata.Authors) > 0 {
			entry := metadata.Authors[0]
			author = formatPersonOrOrg(entry.Name, entry.Email)
		}

	case pkg.RDescription:
		// this is most likely to have a name and email
		author = metadata.Maintainer

		if author == "" {
			author = metadata.Author
		}

	case pkg.NpmPackage:
		author = metadata.Author

	case pkg.PythonPackage:
		author = formatPersonOrOrg(metadata.Author, metadata.AuthorEmail)

	case pkg.RubyGemspec:
		if len(metadata.Authors) > 0 {
			author = metadata.Authors[0]
		}
	case pkg.RpmDBEntry:
		typ = orgType
		author = metadata.Vendor

	case pkg.RpmArchive:
		typ = orgType
		author = metadata.Vendor

	case pkg.WordpressPluginEntry:
		// it seems that the vast majority of the time the author is an org, not a person
		typ = orgType
		author = metadata.Author

	case pkg.SwiplPackEntry:
		author = formatPersonOrOrg(metadata.Author, metadata.AuthorEmail)
	}

	if typ == "" && author != "" {
		typ = personType
	}

	return typ, parseAndFormatPersonOrOrg(author)
}

// Supplier needs to conform to the SPDX spec here:
// https://spdx.github.io/spdx-spec/v2.2.2/package-information/#75-package-supplier-field
//
// Definition:
//
//	Identify the actual distribution source for the package/directory identified in the SPDX document. This might
//	or might not be different from the originating distribution source for the package. The name of the Package Supplier
//	shall be an organization or recognized author and not a web site. For example, SourceForge is a host website, not a
//	supplier, the supplier for https://sourceforge.net/projects/bridge/ is “The Linux Foundation.”
//
// Use NOASSERTION if:
//
//   - the SPDX document creator has attempted to but cannot reach a reasonable objective determination;
//   - the SPDX document creator has made no attempt to determine this field; or
//   - the SPDX document creator has intentionally provided no information (no meaning should be implied by doing so).
//
// Available options are: <omit>, NOASSERTION, Person: <person>, Organization: <org>
// return values are: <type>, <value>
func Supplier(p pkg.Package) (typ string, author string) {
	if !hasMetadata(p) {
		return
	}

	if metadata, ok := p.Metadata.(pkg.AlpmDBEntry); ok {
		// most indications here are that this is the person that is simply packaging the upstream software. Most
		// of the time this is not the original author of the upstream software (which would be the originator).
		// Though it is possible for users to be both the packager and the author, this code cannot distinct this
		// case and sticks to the semantically correct interpretation of the "packager" (which says nothing about the
		// authorship of the upstream software).
		author = metadata.Packager
	}

	if metadata, ok := p.Metadata.(pkg.SwiplPackEntry); ok {
		author = formatPersonOrOrg(metadata.Packager, metadata.PackagerEmail)
	}

	if author == "" {
		// TODO: this uses the Originator function for now until a better distinction can be made for supplier
		return Originator(p)
	}

	if typ == "" && author != "" {
		typ = personType
	}

	return typ, parseAndFormatPersonOrOrg(author)
}

var nameEmailURLPattern = regexp.MustCompile(`^(?P<name>[^<>()]*)( <(?P<email>[^@]+@\w+\.\w+)>)?( \((?P<url>.*)\))?$`)

func parseAndFormatPersonOrOrg(s string) string {
	name, email, _ := parseNameEmailURL(s)
	return formatPersonOrOrg(name, email)
}

func parseNameEmailURL(s string) (name, email, url string) {
	fields := internal.MatchNamedCaptureGroups(nameEmailURLPattern, s)
	name = strings.TrimSpace(fields["name"])
	email = strings.TrimSpace(fields["email"])
	url = strings.TrimSpace(fields["url"])

	if email == "" {
		if approximatesAsEmail(url) {
			email = url
			url = ""
		} else if approximatesAsEmail(name) {
			email = name
			name = ""
		}
	}
	return name, email, url
}

func approximatesAsEmail(s string) bool {
	atIndex := strings.Index(s, "@")
	if atIndex == -1 {
		return false
	}
	dotIndex := strings.Index(s[atIndex:], ".")
	return dotIndex != -1
}

func formatPersonOrOrg(name, email string) string {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)

	blankName := name == ""
	blankEmail := email == ""

	if !blankEmail && !blankName {
		return fmt.Sprintf("%s (%s)", name, email)
	}
	if !blankName && blankEmail {
		return name
	}
	if blankName && !blankEmail {
		return email
	}
	return ""
}
