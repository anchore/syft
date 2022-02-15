package model

import "github.com/anchore/syft/internal/formats/common/spdxhelpers"

type Package struct {
	Item
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
	ExternalRefs []spdxhelpers.ExternalRef `json:"externalRefs,omitempty"`
	// Indicates whether the file content of this package has been available for or subjected to analysis when
	// creating the SPDX document. If false indicates packages that represent metadata or URI references to a
	// project, product, artifact, distribution or a component. If set to false, the package must not contain any files
	FilesAnalyzed bool `json:"filesAnalyzed"`
	// Indicates that a particular file belongs to a package (elements are SPDX ID for a File).
	HasFiles []string `json:"hasFiles,omitempty"`
	// Provide a place for the SPDX file creator to record a web site that serves as the package's home page.
	// This link can also be used to reference further information about the package referenced by the SPDX file creator.
	Homepage string `json:"homepage,omitempty"`
	// List the licenses that have been declared by the authors of the package. Any license information that does not
	// originate from the package authors, e.g. license information from a third party repository, should not be included in this field.
	LicenseDeclared string `json:"licenseDeclared"`
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
}
