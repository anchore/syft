package file

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/anchore/syft/syft/source"
)

func catalogLocationFullyInMemory(resolver source.FileResolver, location source.Location, patterns map[string]*regexp.Regexp) ([]Secret, error) {
	var allSecrets []Secret

	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	defer readCloser.Close()

	contents, err := ioutil.ReadAll(readCloser)
	if err != nil {
		return nil, err
	}

	for name, pattern := range patterns {
		secrets, err := searchForSecret(contents, name, pattern)
		if err != nil {
			return nil, err
		}
		allSecrets = append(allSecrets, secrets...)
	}

	return allSecrets, nil
}

func searchForSecret(contents []byte, name string, pattern *regexp.Regexp) ([]Secret, error) {
	var secrets []Secret
	for _, positions := range pattern.FindAllSubmatchIndex(contents, -1) {
		if len(positions) > 0 {
			index := pattern.SubexpIndex("value")
			if index == -1 {
				// there is no capture group, use the entire expression as the secret value
				start, stop := int64(positions[0]), int64(positions[1])
				secrets = append(secrets, Secret{
					PatternName: name,
					Position:    start,
					Length:      stop - start,
				})
			} else {
				// use the capture group value
				start, stop := int64(positions[index*2]), int64(positions[index*2+1])
				secrets = append(secrets, Secret{
					PatternName: name,
					Position:    start,
					Length:      stop - start,
				})
			}
		}
	}

	return secrets, nil
}
