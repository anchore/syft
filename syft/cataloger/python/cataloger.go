package python

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Cataloger struct {
	cataloger common.GenericCataloger
}

func NewCataloger() *Cataloger {
	// we want to match on partial dir names
	// 	/home/user/requests-2.10.0.dist-info/METADATA
	//	/home/user/requests-2.10.0/dist-info/METADATA
	globParsers := map[string]common.ParserFn{
		"**/*egg-info/PKG-INFO":  parseEggMetadata,
		"**/*dist-info/METADATA": parseWheelMetadata,
		"**/requirements.txt":    parseRequirementsTxt,
		"**/poetry.lock":         parsePoetryLock,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

func (a *Cataloger) Name() string {
	return "python-cataloger"
}

func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
