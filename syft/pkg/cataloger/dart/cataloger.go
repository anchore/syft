/*
Package dart provides a concrete Cataloger implementations for the Dart language ecosystem.
*/
package dart

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPubspecLockCataloger returns a new Dartlang cataloger object base on pubspec lock files.
func NewPubspecLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("dart-pubspec-lock-cataloger").
		WithParserByGlobs(parsePubspecLock, "**/pubspec.lock")
}
