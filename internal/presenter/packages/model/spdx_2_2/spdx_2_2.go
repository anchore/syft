package spdx_2_2

import "time"

// derived from:
// - https://spdx.github.io/spdx-spec/appendix-III-RDF-data-model-implementation-and-identifier-syntax/
// - https://github.com/spdx/spdx-spec/blob/v2.2/schemas/spdx-schema.json
// - https://github.com/spdx/spdx-spec/tree/v2.2/ontology

// ElementID represents the identifier string portion of an SPDX element
// identifier. DocElementID should be used for any attributes which can
// contain identifiers defined in a different SPDX document.
// ElementIDs should NOT contain the mandatory 'SPDXRef-' portion.
type ElementID string

func (e ElementID) String() string {
	return "SPDXRef-" + string(e)
}

// DocElementID represents an SPDX element identifier that could be defined
// in a different SPDX document, and therefore could have a "DocumentRef-"
// portion, such as Relationship and Annotations.
// ElementID is used for attributes in which a "DocumentRef-" portion cannot
// appear, such as a Package or File definition (since it is necessarily
// being defined in the present document).
// DocumentRefID will be the empty string for elements defined in the
// present document.
// DocElementIDs should NOT contain the mandatory 'DocumentRef-' or
// 'SPDXRef-' portions.
type DocElementID struct {
	DocumentRefID string
	ElementRefID  ElementID
}

// RenderDocElementID takes a DocElementID and returns the string equivalent,
// with the SPDXRef- prefix (and, if applicable, the DocumentRef- prefix)
// reinserted.
func (d DocElementID) String() string {
	prefix := ""
	if d.DocumentRefID != "" {
		prefix = "DocumentRef-" + d.DocumentRefID + ":"
	}
	return prefix + d.ElementRefID.String()
}

type Element struct {
	SPDXID string `json:"SPDXID"`
	// Provide additional information about an SpdxElement.
	Annotations []Annotation `json:"annotations,omitempty"`
	Comment     string       `json:"comment,omitempty"`
	// Identify name of this SpdxElement.
	Name string `json:"name"`
	// Relationships referenced in the SPDX document
	Relationships []Relationship `json:"relationships,omitempty"`
}

type Document struct {
	SPDXVersion string `json:"spdxVersion"`
	// One instance is required for each SPDX file produced. It provides the necessary information for forward
	// and backward compatibility for processing tools.
	CreationInfo CreationInfo `json:"creationInfo"`
	// 2.2: Data License; should be "CC0-1.0"
	// Cardinality: mandatory, one
	// License expression for dataLicense.  Compliance with the SPDX specification includes populating the SPDX
	// fields therein with data related to such fields (\"SPDX-Metadata\"). The SPDX specification contains numerous
	// fields where an SPDX document creator may provide relevant explanatory text in SPDX-Metadata. Without
	// opining on the lawfulness of \"database rights\" (in jurisdictions where applicable), such explanatory text
	// is copyrightable subject matter in most Berne Convention countries. By using the SPDX specification, or any
	// portion hereof, you hereby agree that any copyright rights (as determined by your jurisdiction) in any
	// SPDX-Metadata, including without limitation explanatory text, shall be subject to the terms of the Creative
	// Commons CC0 1.0 Universal license. For SPDX-Metadata not containing any copyright rights, you hereby agree
	// and acknowledge that the SPDX-Metadata is provided to you \"as-is\" and without any representations or
	// warranties of any kind concerning the SPDX-Metadata, express, implied, statutory or otherwise, including
	// without limitation warranties of title, merchantability, fitness for a particular purpose, non-infringement,
	// or the absence of latent or other defects, accuracy, or the presence or absence of errors, whether or not
	// discoverable, all to the greatest extent permissible under applicable law.
	DataLicense string `json:"dataLicense"`
	// Information about an external SPDX document reference including the checksum. This allows for verification of the external references.
	ExternalDocumentRefs []ExternalDocumentRef `json:"externalDocumentRefs,omitempty"`
	// Indicates that a particular ExtractedLicensingInfo was defined in the subject SpdxDocument.
	HasExtractedLicensingInfos []HasExtractedLicensingInfo `json:"hasExtractedLicensingInfos,omitempty"`
	// note: found in example documents from SPDX, but not in the JSON schema. See https://spdx.github.io/spdx-spec/2-document-creation-information/#25-spdx-document-namespace
	DocumentNamespace string `json:"documentNamespace"`
	// note: found in example documents from SPDX, but not in the JSON schema
	// DocumentDescribes []string  `json:"documentDescribes"`
	Packages []Package `json:"packages"`
	// Files referenced in the SPDX document
	Files []File `json:"files,omitempty"`
	// Snippets referenced in the SPDX document
	Snippets []Snippet `json:"snippets,omitempty"`
	Element
}

type Item struct {
	// The licenseComments property allows the preparer of the SPDX document to describe why the licensing in
	// spdx:licenseConcluded was chosen.
	LicenseComments  string `json:"licenseComments,omitempty"`
	LicenseConcluded string `json:"licenseConcluded"`
	// The licensing information that was discovered directly within the package. There will be an instance of this
	// property for each distinct value of alllicenseInfoInFile properties of all files contained in the package.
	LicenseInfoFromFiles []string `json:"licenseInfoFromFiles,omitempty"`
	// Licensing information that was discovered directly in the subject file. This is also considered a declared license for the file.
	LicenseInfoInFiles []string `json:"licenseInfoInFiles,omitempty"`
	// The text of copyright declarations recited in the Package or File.
	CopyrightText string `json:"copyrightText,omitempty"`
	// This field provides a place for the SPDX data creator to record acknowledgements that may be required to be
	// communicated in some contexts. This is not meant to include the actual complete license text (see
	// licenseConculded and licenseDeclared), and may or may not include copyright notices (see also copyrightText).
	// The SPDX data creator may use this field to record other acknowledgements, such as particular clauses from
	// license texts, which may be necessary or desirable to reproduce.
	AttributionTexts []string `json:"attributionTexts,omitempty"`
	Element
}

type CreationInfo struct {
	Comment string `json:"comment,omitempty"`
	// Identify when the SPDX file was originally created. The date is to be specified according to combined date and
	// time in UTC format as specified in ISO 8601 standard. This field is distinct from the fields in section 8,
	// which involves the addition of information during a subsequent review.
	Created time.Time `json:"created"`
	// Identify who (or what, in the case of a tool) created the SPDX file. If the SPDX file was created by an
	// individual, indicate the person's name. If the SPDX file was created on behalf of a company or organization,
	//indicate the entity name. If the SPDX file was created using a software tool, indicate the name and version
	// for that tool. If multiple participants or tools were involved, use multiple instances of this field. Person
	// name or organization name may be designated as “anonymous” if appropriate.
	Creators []string `json:"creators"`
	// An optional field for creators of the SPDX file to provide the version of the SPDX License List used when the SPDX file was created.
	LicenseListVersion string `json:"licenseListVersion,omitempty"`
}
type Checksum struct {
	// Identifies the algorithm used to produce the subject Checksum. One of: "SHA256", "SHA1", "SHA384", "MD2", "MD4", "SHA512", "MD6", "MD5", "SHA224"
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}
type ExternalDocumentRef struct {
	// externalDocumentId is a string containing letters, numbers, ., - and/or + which uniquely identifies an external document within this document.
	ExternalDocumentID string   `json:"externalDocumentId"`
	Checksum           Checksum `json:"checksum"`
	// SPDX ID for SpdxDocument.  A propoerty containing an SPDX document.
	SpdxDocument string `json:"spdxDocument"`
}
type HasExtractedLicensingInfo struct {
	// Verbatim license or licensing notice text that was discovered.
	ExtractedText string `json:"extractedText"`
	// A human readable short form license identifier for a license. The license ID is iether on the standard license
	// oist or the form \"LicenseRef-\"[idString] where [idString] is a unique string containing letters,
	// numbers, \".\", \"-\" or \"+\".
	LicenseID string `json:"licenseId"`
	Comment   string `json:"comment,omitempty"`
	// Identify name of this SpdxElement.
	Name     string   `json:"name,omitempty"`
	SeeAlsos []string `json:"seeAlsos,omitempty"`
}

type AnnotationType string

const (
	ReviewerAnnotationType AnnotationType = "REVIEWER"
	OtherAnnotationType    AnnotationType = "OTHER"
)

type Annotation struct {
	// Identify when the comment was made. This is to be specified according to the combined date and time in the
	// UTC format, as specified in the ISO 8601 standard.
	AnnotationDate time.Time `json:"annotationDate"`
	// Type of the annotation
	AnnotationType AnnotationType `json:"annotationType"`
	// This field identifies the person, organization or tool that has commented on a file, package, or the entire document.
	Annotator string `json:"annotator"`
	Comment   string `json:"comment"`
}

type ReferenceCategory string

const (
	SecurityReferenceCategory       ReferenceCategory = "SECURITY"
	PackageManagerReferenceCategory ReferenceCategory = "PACKAGE_MANAGER"
	OtherReferenceCategory          ReferenceCategory = "OTHER"
)

// source: https://spdx.github.io/spdx-spec/appendix-VI-external-repository-identifiers/

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

// Why are there two package identifier fields Package Checksum and Package Verification?
// Although the values of the two fields Package Checksum and Package Verification are similar, they each serve a
// different purpose. The Package Checksum provides a unique identifier of a software package which is computed by
// taking the SHA1 of the entire software package file. This enables one to quickly determine if two different copies
// of a package are the same. One disadvantage of this approach is that one cannot add an SPDX data file into the
// original package without changing the Package Checksum value. Alternatively, the Package Verification field enables
// the inclusion of an SPDX file. It enables one to quickly verify if one or more of the original package files has
// changed. The Package Verification field is a unique identifier that is based on SHAing only the original package
// files (e.g., excluding the SPDX file). This allows one to add an SPDX file to the original package without changing
// this unique identifier.
// source: https://wiki.spdx.org/view/SPDX_FAQ
type PackageVerificationCode struct {
	// "A file that was excluded when calculating the package verification code. This is usually a file containing
	// SPDX data regarding the package. If a package contains more than one SPDX file all SPDX files must be excluded
	// from the package verification code. If this is not done it would be impossible to correctly calculate the
	// verification codes in both files.
	PackageVerificationCodeExcludedFiles []string `json:"packageVerificationCodeExcludedFiles"`

	// The actual package verification code as a hex encoded value.
	PackageVerificationCodeValue string `json:"packageVerificationCodeValue"`
}
type Package struct {
	// The checksum property provides a mechanism that can be used to verify that the contents of a File or
	// Package have not changed.
	Checksums []Checksum `json:"checksums,omitempty"`
	// Provides a detailed description of the package.
	Description string `json:"description,omitempty"`
	// The URI at which this package is available for download. Private (i.e., not publicly reachable) URIs are
	// acceptable as values of this property. The values http://spdx.org/rdf/terms#none and http://spdx.org/rdf/terms#noassertion
	// may be used to specify that the package is not downloadable or that no attempt was made to determine its
	// download location, respectively.
	DownloadLocation string `json:"downloadLocation,omitempty"`
	// An External Reference allows a Package to reference an external source of additional information, metadata,
	// enumerations, asset identifiers, or downloadable content believed to be relevant to the Package.
	ExternalRefs []ExternalRef `json:"externalRefs,omitempty"`
	// Indicates whether the file content of this package has been available for or subjected to analysis when
	// creating the SPDX document. If false indicates packages that represent metadata or URI references to a
	// project, product, artifact, distribution or a component. If set to false, the package must not contain any files
	FilesAnalyzed bool `json:"filesAnalyzed"`
	// Indicates that a particular file belongs to a package (elements are SPDX ID for a File).
	HasFiles        []string `json:"hasFiles,omitempty"`
	Homepage        string   `json:"homepage,omitempty"`
	LicenseDeclared string   `json:"licenseDeclared"`
	// The name and, optionally, contact information of the person or organization that originally created the package.
	// Values of this property must conform to the agent and tool syntax.
	Originator string `json:"originator,omitempty"`
	// The base name of the package file name. For example, zlib-1.2.5.tar.gz.
	PackageFileName string `json:"packageFileName,omitempty"`
	// A manifest based verification code (the algorithm is defined in section 4.7 of the full specification) of the
	// SPDX Item. This allows consumers of this data and/or database to determine if an SPDX item they have in hand
	// is identical to the SPDX item from which the data was produced. This algorithm works even if the SPDX document
	// is included in the SPDX item.
	PackageVerificationCode *PackageVerificationCode `json:"packageVerificationCode,omitempty"`
	// Allows the producer(s) of the SPDX document to describe how the package was acquired and/or changed from the original source.
	SourceInfo string `json:"sourceInfo,omitempty"`
	// Provides a short description of the package.
	Summary string `json:"summary,omitempty"`
	// The name and, optionally, contact information of the person or organization who was the immediate supplier
	// of this package to the recipient. The supplier may be different than originator when the software has been
	// repackaged. Values of this property must conform to the agent and tool syntax.
	Supplier string `json:"supplier,omitempty"`
	// Provides an indication of the version of the package that is described by this SpdxDocument.
	VersionInfo string `json:"versionInfo,omitempty"`
	Item
}

type FileType string

const (
	DocumentationFileType FileType = "DOCUMENTATION"
	ImageFileType         FileType = "IMAGE"
	VideoFileType         FileType = "VIDEO"
	ArchiveFileType       FileType = "ARCHIVE"
	SpdxFileType          FileType = "SPDX"
	ApplicationFileType   FileType = "APPLICATION"
	SourceFileType        FileType = "SOURCE"
	BinaryFileType        FileType = "BINARY"
	TextFileType          FileType = "TEXT"
	AudioFileType         FileType = "AUDIO"
	OtherFileType         FileType = "OTHER"
)

type File struct {
	// (At least one is required.) The checksum property provides a mechanism that can be used to verify that the
	// contents of a File or Package have not changed.
	Checksums []Checksum `json:"checksums"`
	// This field provides a place for the SPDX file creator to record file contributors. Contributors could include
	// names of copyright holders and/or authors who may not be copyright holders yet contributed to the file content.
	FileContributors []string `json:"fileContributors"`
	// Each element is a SPDX ID for a File.
	FileDependencies []string `json:"fileDependencies"`
	// The name of the file relative to the root of the package.
	FileName string `json:"fileName"`
	// The type of the file
	FileTypes []string `json:"fileTypes"`
	// This field provides a place for the SPDX file creator to record potential legal notices found in the file.
	// This may or may not include copyright statements.
	NoticeText string `json:"noticeText,omitempty"`
	// Indicates the project in which the SpdxElement originated. Tools must preserve doap:homepage and doap:name
	// properties and the URI (if one is known) of doap:Project resources that are values of this property. All other
	// properties of doap:Projects are not directly supported by SPDX and may be dropped when translating to or
	// from some SPDX formats.
	ArtifactOf []string `json:"artifactOf"`
	Item
}

type StartPointer struct {
	Offset     int `json:"offset,omitempty"`
	LineNumber int `json:"lineNumber,omitempty"`
	// SPDX ID for File
	Reference string `json:"reference"`
}

type EndPointer struct {
	Offset     int `json:"offset,omitempty"`
	LineNumber int `json:"lineNumber,omitempty"`
	// SPDX ID for File
	Reference string `json:"reference"`
}

type Range struct {
	StartPointer StartPointer `json:"startPointer"`
	EndPointer   EndPointer   `json:"endPointer"`
}

type Snippet struct {
	// Licensing information that was discovered directly in the subject snippet. This is also considered a declared
	// license for the snippet. (elements are license expressions)
	LicenseInfoInSnippets []string `json:"licenseInfoInSnippets"`
	// SPDX ID for File. File containing the SPDX element (e.g. the file contaning a snippet).
	SnippetFromFile string `json:"snippetFromFile"`
	// (At least 1 range is required). This field defines the byte range in the original host file (in X.2) that the
	// snippet information applies to.
	Ranges []Range `json:"ranges"`
	Item
}
type Relationship struct {
	// SPDX ID for SpdxElement.  A related SpdxElement.
	RelatedSpdxElement string `json:"relatedSpdxElement"`
	// Describes the type of relationship between two SPDX elements.
	RelationshipType RelationshipType `json:"relationshipType"`
	Comment          string           `json:"comment,omitempty"`
}

// source: https://spdx.github.io/spdx-spec/7-relationships-between-SPDX-elements/
type RelationshipType string

const (
	// DescribedByRelationship is to be used when SPDXRef-A is described by SPDXREF-Document.
	// Example: The package 'WildFly' is described by SPDX document WildFly.spdx.
	DescribedByRelationship RelationshipType = "DESCRIBED_BY"

	// ContainsRelationship is to be used when SPDXRef-A contains SPDXRef-B.
	// Example: An ARCHIVE file bar.tgz contains a SOURCE file foo.c.
	ContainsRelationship RelationshipType = "CONTAINS"

	// ContainedByRelationship is to be used when SPDXRef-A is contained by SPDXRef-B.
	// Example: A SOURCE file foo.c is contained by ARCHIVE file bar.tgz
	ContainedByRelationship RelationshipType = "CONTAINED_BY"

	// DependsOnRelationship is to be used when SPDXRef-A depends on SPDXRef-B.
	// Example: Package A depends on the presence of package B in order to build and run
	DependsOnRelationship RelationshipType = "DEPENDS_ON"

	// DependencyOfRelationship is to be used when SPDXRef-A is dependency of SPDXRef-B.
	// Example: A is explicitly stated as a dependency of B in a machine-readable file. Use when a package manager does not define scopes.
	DependencyOfRelationship RelationshipType = "DEPENDENCY_OF"

	// DependencyManifestOfRelationship is to be used when SPDXRef-A is a manifest file that lists a set of dependencies for SPDXRef-B.
	// Example: A file package.json is the dependency manifest of a package foo. Note that only one manifest should be used to define the same dependency graph.
	DependencyManifestOfRelationship RelationshipType = "DEPENDENCY_MANIFEST_OF"

	// BuildDependencyOfRelationship is to be used when SPDXRef-A is a build dependency of SPDXRef-B.
	// Example: A is in the compile scope of B in a Maven project.
	BuildDependencyOfRelationship RelationshipType = "BUILD_DEPENDENCY_OF"

	// DevDependencyOfRelationship is to be used when SPDXRef-A is a development dependency of SPDXRef-B.
	// Example: A is in the devDependencies scope of B in a Maven project.
	DevDependencyOfRelationship RelationshipType = "DEV_DEPENDENCY_OF"

	// OptionalDependencyOfRelationship is to be used when SPDXRef-A is an optional dependency of SPDXRef-B.
	// Example: Use when building the code will proceed even if a dependency cannot be found, fails to install, or is only installed on a specific platform. For example, A is in the optionalDependencies scope of npm project B.
	OptionalDependencyOfRelationship RelationshipType = "OPTIONAL_DEPENDENCY_OF"

	// ProvidedDependencyOfRelationship is to be used when SPDXRef-A is a to be provided dependency of SPDXRef-B.
	// Example: A is in the provided scope of B in a Maven project, indicating that the project expects it to be provided, for instance, by the container or JDK.
	ProvidedDependencyOfRelationship RelationshipType = "PROVIDED_DEPENDENCY_OF"

	// TestDependencyOfRelationship is to be used when SPDXRef-A is a test dependency of SPDXRef-B.
	// Example: A is in the test scope of B in a Maven project.
	TestDependencyOfRelationship RelationshipType = "TEST_DEPENDENCY_OF"

	// RuntimeDependencyOfRelationship is to be used when SPDXRef-A is a dependency required for the execution of SPDXRef-B.
	// Example: A is in the runtime scope of B in a Maven project.
	RuntimeDependencyOfRelationship RelationshipType = "RUNTIME_DEPENDENCY_OF"

	// ExampleOfRelationship is to be used when SPDXRef-A is an example of SPDXRef-B.
	// Example: The file or snippet that illustrates how to use an application or library.
	ExampleOfRelationship RelationshipType = "EXAMPLE_OF"

	// GeneratesRelationship is to be used when SPDXRef-A generates SPDXRef-B.
	// Example: A SOURCE file makefile.mk generates a BINARY file a.out
	GeneratesRelationship RelationshipType = "GENERATES"

	// GeneratedFromRelationship is to be used when SPDXRef-A was generated from SPDXRef-B.
	// Example: A BINARY file a.out has been generated from a SOURCE file makefile.mk. A BINARY file foolib.a is generated from a SOURCE file bar.c.
	GeneratedFromRelationship RelationshipType = "GENERATED_FROM"

	// AncestorOfRelationship is to be used when SPDXRef-A is an ancestor (same lineage but pre-dates) SPDXRef-B.
	// Example: A SOURCE file makefile.mk is a version of the original ancestor SOURCE file 'makefile2.mk'
	AncestorOfRelationship RelationshipType = "ANCESTOR_OF"

	// DescendantOfRelationship is to be used when SPDXRef-A is a descendant of (same lineage but postdates) SPDXRef-B.
	// Example: A SOURCE file makefile2.mk is a descendant of the original SOURCE file 'makefile.mk'
	DescendantOfRelationship RelationshipType = "DESCENDANT_OF"

	// VariantOfRelationship is to be used when SPDXRef-A is a variant of (same lineage but not clear which came first) SPDXRef-B.
	// Example: A SOURCE file makefile2.mk is a variant of SOURCE file makefile.mk if they differ by some edit, but there is no way to tell which came first (no reliable date information).
	VariantOfRelationship RelationshipType = "VARIANT_OF"

	// DistributionArtifactRelationship is to be used when distributing SPDXRef-A requires that SPDXRef-B also be distributed.
	// Example: A BINARY file foo.o requires that the ARCHIVE file bar-sources.tgz be made available on distribution.
	DistributionArtifactRelationship RelationshipType = "DISTRIBUTION_ARTIFACT"

	// PatchForRelationship is to be used when SPDXRef-A is a patch file for (to be applied to) SPDXRef-B.
	// Example: A SOURCE file foo.diff is a patch file for SOURCE file foo.c.
	PatchForRelationship RelationshipType = "PATCH_FOR"

	// PatchAppliedRelationship is to be used when SPDXRef-A is a patch file that has been applied to SPDXRef-B.
	// Example: A SOURCE file foo.diff is a patch file that has been applied to SOURCE file 'foo-patched.c'.
	PatchAppliedRelationship RelationshipType = "PATCH_APPLIED"

	// CopyOfRelationship is to be used when SPDXRef-A is an exact copy of SPDXRef-B.
	// Example: A BINARY file alib.a is an exact copy of BINARY file a2lib.a.
	CopyOfRelationship RelationshipType = "COPY_OF"

	// FileAddedRelationship is to be used when SPDXRef-A is a file that was added to SPDXRef-B.
	// Example: A SOURCE file foo.c has been added to package ARCHIVE bar.tgz.
	FileAddedRelationship RelationshipType = "FILE_ADDED"

	// FileDeletedRelationship is to be used when SPDXRef-A is a file that was deleted from SPDXRef-B.
	// Example: A SOURCE file foo.diff has been deleted from package ARCHIVE bar.tgz.
	FileDeletedRelationship RelationshipType = "FILE_DELETED"

	// FileModifiedRelationship is to be used when SPDXRef-A is a file that was modified from SPDXRef-B.
	// Example: A SOURCE file foo.c has been modified from SOURCE file foo.orig.c.
	FileModifiedRelationship RelationshipType = "FILE_MODIFIED"

	// ExpandedFromArchiveRelationship is to be used when SPDXRef-A is expanded from the archive SPDXRef-B.
	// Example: A SOURCE file foo.c, has been expanded from the archive ARCHIVE file xyz.tgz.
	ExpandedFromArchiveRelationship RelationshipType = "EXPANDED_FROM_ARCHIVE"

	// DynamicLinkRelationship is to be used when SPDXRef-A dynamically links to SPDXRef-B.
	// Example: An APPLICATION file 'myapp' dynamically links to BINARY file zlib.so.
	DynamicLinkRelationship RelationshipType = "DYNAMIC_LINK"

	// StaticLinkRelationship is to be used when SPDXRef-A statically links to SPDXRef-B.
	// Example: An APPLICATION file 'myapp' statically links to BINARY zlib.a.
	StaticLinkRelationship RelationshipType = "STATIC_LINK"

	// DataFileOfRelationship is to be used when SPDXRef-A is a data file used in SPDXRef-B.
	// Example: An IMAGE file 'kitty.jpg' is a data file of an APPLICATION 'hellokitty'.
	DataFileOfRelationship RelationshipType = "DATA_FILE_OF"

	// TestCaseOfRelationship is to be used when SPDXRef-A is a test case used in testing SPDXRef-B.
	// Example: A SOURCE file testMyCode.java is a unit test file used to test an APPLICATION MyPackage.
	TestCaseOfRelationship RelationshipType = "TEST_CASE_OF"

	// BuildToolOfRelationship is to be used when SPDXRef-A is used to build SPDXRef-B.
	// Example: A SOURCE file makefile.mk is used to build an APPLICATION 'zlib'.
	BuildToolOfRelationship RelationshipType = "BUILD_TOOL_OF"

	// DevToolOfRelationship is to be used when SPDXRef-A is used as a development tool for SPDXRef-B.
	// Example: Any tool used for development such as a code debugger.
	DevToolOfRelationship RelationshipType = "DEV_TOOL_OF"

	// TestOfRelationship is to be used when SPDXRef-A is used for testing SPDXRef-B.
	// Example: Generic relationship for cases where it's clear that something is used for testing but unclear whether it's TEST_CASE_OF or TEST_TOOL_OF.
	TestOfRelationship RelationshipType = "TEST_OF"

	// TestToolOfRelationship is to be used when SPDXRef-A is used as a test tool for SPDXRef-B.
	// Example: Any tool used to test the code such as ESlint.
	TestToolOfRelationship RelationshipType = "TEST_TOOL_OF"

	// DocumentationOfRelationship is to be used when SPDXRef-A provides documentation of SPDXRef-B.
	// Example: A DOCUMENTATION file readme.txt documents the APPLICATION 'zlib'.
	DocumentationOfRelationship RelationshipType = "DOCUMENTATION_OF"

	// OptionalComponentOfRelationship is to be used when SPDXRef-A is an optional component of SPDXRef-B.
	// Example: A SOURCE file fool.c (which is in the contributors directory) may or may not be included in the build of APPLICATION 'atthebar'.
	OptionalComponentOfRelationship RelationshipType = "OPTIONAL_COMPONENT_OF"

	// MetafileOfRelationship is to be used when SPDXRef-A is a metafile of SPDXRef-B.
	// Example: A SOURCE file pom.xml is a metafile of the APPLICATION 'Apache Xerces'.
	MetafileOfRelationship RelationshipType = "METAFILE_OF"

	// PackageOfRelationship is to be used when SPDXRef-A is used as a package as part of SPDXRef-B.
	// Example: A Linux distribution contains an APPLICATION package gawk as part of the distribution MyLinuxDistro.
	PackageOfRelationship RelationshipType = "PACKAGE_OF"

	// AmendsRelationship is to be used when (current) SPDXRef-DOCUMENT amends the SPDX information in SPDXRef-B.
	// Example: (Current) SPDX document A version 2 contains a correction to a previous version of the SPDX document A version 1. Note the reserved identifier SPDXRef-DOCUMENT for the current document is required.
	AmendsRelationship RelationshipType = "AMENDS"

	// PrerequisiteForRelationship is to be used when SPDXRef-A is a prerequisite for SPDXRef-B.
	// Example: A library bar.dll is a prerequisite or dependency for APPLICATION foo.exe
	PrerequisiteForRelationship RelationshipType = "PREREQUISITE_FOR"

	// HasPrerequisiteRelationship is to be used when SPDXRef-A has as a prerequisite SPDXRef-B.
	// Example: An APPLICATION foo.exe has prerequisite or dependency on bar.dll
	HasPrerequisiteRelationship RelationshipType = "HAS_PREREQUISITE"

	// OtherRelationship is to be used for a relationship which has not been defined in the formal SPDX specification. A description of the relationship should be included in the Relationship comments field.
	OtherRelationship RelationshipType = "OTHER"
)
