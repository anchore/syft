package swift

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"gopkg.in/yaml.v3"
)

// integrity check
var _ common.ParserFn = parsePodfileLock

// parsePodfileLock is a parser function for Podfile.lock contents, returning all cocoapods pods discovered.
func parsePodfileLock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read file: %w", err)
	}
	var podfile map[string]interface{}
	if err = yaml.Unmarshal(bytes, &podfile); err != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml: %w", err)
	}

	c, exists := podfile["SPEC CHECKSUMS"]
	if !exists {
		return nil, nil, fmt.Errorf("malformed podfile.lock: missing checksums")
	}
	checksums := c.(map[string]interface{})
	p, exists := podfile["PODS"]
	if !exists {
		return nil, nil, fmt.Errorf("malformed podfile.lock: missing checksums")
	}
	pods := p.([]interface{})

	pkgs := []*pkg.Package{}
	for _, podInterface := range pods {
		var podBlob string
		switch v := podInterface.(type) {
		case map[string]interface{}:
			for k := range v {
				podBlob = k
			}
		case string:
			podBlob = v
		default:
			return nil, nil, fmt.Errorf("malformed podfile.lock")
		}
		splits := strings.Split(podBlob, " ")
		podName := splits[0]
		podVersion := strings.TrimSuffix(strings.TrimPrefix(splits[1], "("), ")")
		podRootPkg := strings.Split(podName, "/")[0]
		pkgHash, exists := checksums[podRootPkg]
		if !exists {
			return nil, nil, fmt.Errorf("malformed podfile.lock: incomplete checksums")
		}
		pkgs = append(pkgs, &pkg.Package{
			Name:         podName,
			Version:      podVersion,
			Type:         pkg.CocoapodsPkg,
			Language:     pkg.Swift,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    podName,
				Version: podVersion,
				PkgHash: pkgHash.(string),
			},
		})
	}

	return pkgs, nil, nil
}
