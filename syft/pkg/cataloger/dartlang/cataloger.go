package dartlang

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

type Cataloger struct{}

// NewPubspecLockCataloger returns a new Dartlang cataloger object base on pubspec lock files.
func NewPubspecLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/pubspec.lock": parsePubspecLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "dartlang-lock-cataloger")
}
