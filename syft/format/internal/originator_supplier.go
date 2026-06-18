package internal

import (
	"fmt"
	"regexp"
	"strings"

	syftinternal "github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

const (
	orgType    = "Organization"
	personType = "Person"
)

// Originator returns the person or organization that the package originally came from, derived from
// available package metadata. It needs to conform to the SPDX spec here:
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
func Originator(p pkg.Package) (typ string, author string) {
	typ, author = originatorRaw(p)
	return typ, parseAndFormatPersonOrOrg(author)
}

// originatorRaw returns the originator type and the raw (unformatted) author string straight from the
// package metadata, so callers can either format it as a single string (Originator) or break it into
// its name/email/url parts.
func originatorRaw(p pkg.Package) (typ string, author string) { //nolint: gocyclo,funlen
	if p.Metadata == nil {
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
	case pkg.PEBinary:
		// this is a known common keyword used in version resources
		// for more info see: https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource
		val, ok := metadata.VersionResources.Get("CompanyName")
		if ok {
			typ = orgType
			author = val
		}

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

	case pkg.LinuxKernel:
		author = metadata.Author

	case pkg.LinuxKernelModule:
		author = metadata.Author

	case pkg.ELFBinaryPackageNoteJSONPayload:
		typ = orgType
		author = metadata.Vendor

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
		author = rpmAuthor(metadata.Vendor, metadata.Packager)

	case pkg.RpmArchive:
		typ = orgType
		author = rpmAuthor(metadata.Vendor, metadata.Packager)

	case pkg.WordpressPluginEntry:
		// it seems that the vast majority of the time the author is an org, not a person
		typ = orgType
		author = metadata.Author

	case pkg.SwiplPackEntry:
		author = formatPersonOrOrg(metadata.Author, metadata.AuthorEmail)

	case pkg.VcpkgManifest:
		if len(metadata.Maintainers) > 0 {
			author = metadata.Maintainers[0]
		}
	}

	if typ == "" && author != "" {
		typ = personType
	}

	return typ, author
}

// Supplier returns the actual distribution source for the package, derived from available package
// metadata, falling back to the Originator when no distinct supplier can be determined. It needs to
// conform to the SPDX spec here:
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
	typ, author = supplierRaw(p)
	return typ, parseAndFormatPersonOrOrg(author)
}

// SupplierParts returns the supplier broken into its structured components (entity type, display name,
// email, and URL). Formats with dedicated contact and URL fields can use this to populate them
// individually rather than collapsing everything into a single name string. All parts may be empty
// when no supplier can be determined.
func SupplierParts(p pkg.Package) (typ, name, email, url string) {
	typ, author := supplierRaw(p)
	name, email, url = parseNameEmailURL(author)
	return typ, name, email, url
}

// supplierRaw returns the supplier type and the raw (unformatted) author string straight from the
// package metadata, falling back to the originator when no distinct supplier can be determined.
func supplierRaw(p pkg.Package) (typ string, author string) {
	if p.Metadata == nil {
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
		// TODO: this uses the originator logic for now until a better distinction can be made for supplier
		return originatorRaw(p)
	}

	if typ == "" && author != "" {
		typ = personType
	}

	return typ, author
}

// rpmPackagerContact captures the contact carried inside the angle brackets of an RPM Packager value,
// which is commonly either an email (e.g. "Rocky Linux Build System (Peridot) <releng@rockylinux.org>")
// or a bug-tracker URL (e.g. "Red Hat, Inc. <http://bugzilla.redhat.com/bugzilla>").
var rpmPackagerContact = regexp.MustCompile(`<([^<>]+)>`)

// rpmAuthor combines the RPM Vendor (the supplier organization) with the contact carried in the
// Packager tag, which commonly holds either an email or a bug-tracker URL. The Vendor is used as the
// name, falling back to the Packager's leading text when Vendor is absent.
func rpmAuthor(vendor, packager string) string {
	name := vendor
	contact := ""

	if m := rpmPackagerContact.FindStringSubmatch(packager); len(m) == 2 {
		// "Name (qualifier) <contact>" — the contact lives inside the angle brackets
		contact = strings.TrimSpace(m[1])
		if name == "" {
			name = packagerName(packager)
		}
	} else if approximatesAsEmail(packager) {
		// bare email packager with no name, e.g. "builder@centos.org"
		contact = strings.TrimSpace(packager)
	} else if name == "" {
		// freeform packager with no extractable contact; use it as the name
		name = strings.TrimSpace(packager)
	}

	switch {
	case name == "":
		return contact // may be "" when nothing is extractable
	case contact == "":
		return name
	default:
		// parseNameEmailURL classifies the parenthesized contact as an email or URL
		return fmt.Sprintf("%s (%s)", name, contact)
	}
}

// packagerName returns the organization/person portion of an RPM Packager value: the text before the
// first "<" (contact) or "(" (build-id qualifier). It returns "" when the value leads with one of those.
func packagerName(packager string) string {
	name := packager
	if i := strings.IndexAny(name, "<("); i >= 0 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

// nameEmailURLPattern parses a "name <email> (url)" string. The email sub-expression [^@<>]+@[^@<>]+
// cannot run past the closing '>' that delimits it, while dots and hyphens in multi-level domains
// (e.g. lists.alpinelinux.org) pass through freely. Bare addresses with no angle brackets are not
// matched here; parseNameEmailURL routes those through approximatesAsEmail.
//
// The url sub-expression is [^)]* (not .*) so it stops at the first closing paren rather than running
// greedily to the last one. npm author fields can list multiple authors separated by commas
// (e.g. "A <a@x> (http://a), B <b@y> (http://b)"); the trailing (,.*)? tolerates that remainder so only
// the first author is captured, keeping the url a single valid value rather than a concatenation.
var nameEmailURLPattern = regexp.MustCompile(`^(?P<name>[^<>()]*)( <(?P<email>[^@<>]+@[^@<>]+)>)?( \((?P<url>[^)]*)\))?(,.*)?$`)

func parseAndFormatPersonOrOrg(s string) string {
	name, email, _ := parseNameEmailURL(s)
	return formatPersonOrOrg(name, email)
}

func parseNameEmailURL(s string) (name, email, url string) {
	fields := syftinternal.MatchNamedCaptureGroups(nameEmailURLPattern, s)
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
