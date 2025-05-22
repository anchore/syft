package binary

import "github.com/anchore/syft/syft/pkg/cataloger/internal/binutils"

// Note: all generic utilities for catalogers have been moved to the internal/binutils package.

// Deprecated: This package is deprecated and will be removed in syft v2
type Classifier = binutils.Classifier

// Deprecated: This package is deprecated and will be removed in syft v2
type EvidenceMatcher = binutils.EvidenceMatcher

// Deprecated: This package is deprecated and will be removed in syft v2
func FileContentsVersionMatcher(
	pattern string,
) EvidenceMatcher {
	return binutils.FileContentsVersionMatcher(pattern, catalogerName)
}
