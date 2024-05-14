package helpers

type ReferenceCategory string

const (
	SecurityReferenceCategory       ReferenceCategory = "SECURITY"
	PackageManagerReferenceCategory ReferenceCategory = "PACKAGE-MANAGER"
	OtherReferenceCategory          ReferenceCategory = "OTHER"
)

// source: https://spdx.github.io/spdx-spec/v2.2.2/external-repository-identifiers/

type ExternalRefType string

const (
	// see https://nvd.nist.gov/cpe
	Cpe22ExternalRefType ExternalRefType = "cpe22Type"
	// see https://nvd.nist.gov/cpe
	Cpe23ExternalRefType ExternalRefType = "cpe23Type"
	// see http://repo1.maven.org/maven2/
	MavenCentralExternalRefType ExternalRefType = "maven-central"
	// see https://www.npmjs.com/
	NpmExternalRefType ExternalRefType = "npm"
	// see https://www.nuget.org/
	NugetExternalRefType ExternalRefType = "nuget"
	// see http://bower.io/
	BowerExternalRefType ExternalRefType = "bower"
	// see https://github.com/package-url/purl-spec
	PurlExternalRefType ExternalRefType = "purl"
	// These point to objects present in the Software Heritage archive by the means of SoftWare Heritage persistent Identifiers (SWHID)
	SwhExternalRefType ExternalRefType = "swh"
)

type ExternalRef struct {
	Comment string `json:"comment,omitempty"`
	// Category for the external reference.
	ReferenceCategory ReferenceCategory `json:"referenceCategory"`
	// The unique string with no spaces necessary to access the package-specific information, metadata, or content
	// within the target location. The format of the locator is subject to constraints defined by the <type>.
	ReferenceLocator string `json:"referenceLocator"`
	// Type of the external reference. These are defined in an appendix in the SPDX specification.
	ReferenceType ExternalRefType `json:"referenceType"`
}
