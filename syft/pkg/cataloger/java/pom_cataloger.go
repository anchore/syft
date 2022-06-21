package java

import "github.com/anchore/syft/syft/pkg/cataloger/common"

const javaPomCataloger = "java-pom-cataloger"

// NewJavaProjectCataloger returns a cataloger capable of parsing
// dependency from pom.xml files.
// Pom files list dependencies that maybe not be locally installed yet.
func NewJavaPomCataloger() *common.GenericCataloger {
	globParsers := make(map[string]common.ParserFn)

	// java project files
	globParsers[pomXMLDirGlob] = parserPomXML

	return common.NewGenericCataloger(nil, globParsers, javaPomCataloger)
}
