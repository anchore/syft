/*
Package dart provides a concrete Cataloger implementations for the Dart language ecosystem.
*/
package dart

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPubspecLockCataloger returns a new Dartlang cataloger object base on pubspec lock files.
func NewPubspecLockCataloger() pkg.CatalogerWithRelease {
	return generic.NewCataloger("dart-pubspec-lock-cataloger").
		WithParserByGlobs(parsePubspecLock, "**/pubspec.lock")
}

// NewPubspecCataloger returns a new Dartlang cataloger object base on pubspec files.
func NewPubspecCataloger() pkg.CatalogerWithRelease {
	return generic.NewCataloger("dart-pubspec-cataloger").
		WithParserByGlobs(parsePubspec, "**/pubspec.yml", "**/pubspec.yaml")
}
