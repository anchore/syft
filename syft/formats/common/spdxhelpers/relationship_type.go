package spdxhelpers

// source: https://spdx.github.io/spdx-spec/7-relationships-between-SPDX-elements/
type RelationshipType string

const (
	// DescribedByRelationship is to be used when SPDXRef-A is described by SPDXREF-Document.
	// Example: The package 'WildFly' is described by SPDX document WildFly.spdx.
	DescribedByRelationship RelationshipType = "DESCRIBED_BY"

	// Describes is to be used when SPDXRef-DOCUMENT describes SPDXRef-A.
	// Example: An SPDX document WildFly.spdx describes package ‘WildFly’.
	// Note this is a logical relationship to help organize related items within an SPDX document that is mandatory if more than one package or set of files (not in a package) is present.
	DescribesRelationship RelationshipType = "DESCRIBES"

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
