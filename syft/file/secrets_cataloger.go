package file

import (
	"bytes"
	"fmt"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/event/monitor"
	"io"
	"io/ioutil"
	"regexp"
	"sort"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

var DefaultSecretsPatterns = map[string]string{
	"aws-access-key":     `(?i)aws_access_key_id["'=:\s]*?(?P<value>(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`,
	"aws-secret-key":     `(?i)aws_secret_access_key["'=:\s]*?(?P<value>[0-9a-zA-Z/+]{40})`,
	"pem-private-key":    `-----BEGIN (\S+ )?PRIVATE KEY(\sBLOCK)?-----((?P<value>(\n.*?)+)-----END (\S+ )?PRIVATE KEY(\sBLOCK)?-----)?`,
	"docker-config-auth": `"auths"((.*\n)*.*?"auth"\s*:\s*"(?P<value>[^"]+)")?`,
	"generic-api-key":    `(?i)api(-|_)?key["'=:\s]*?(?P<value>[A-Z0-9]{20,60})["']?(\s|$)`,
}

type SecretsCatalogerConfig struct {
	Patterns     map[string]*regexp.Regexp
	RevealValues bool
	MaxFileSize  int64
}

type SecretsCataloger struct {
	config SecretsCatalogerConfig
}

func DefaultSecretsCatalogerConfig() SecretsCatalogerConfig {
	patterns, err := GenerateSearchPatterns(DefaultSecretsPatterns, nil, nil)
	if err != nil {
		patterns = make(map[string]*regexp.Regexp)
		log.Errorf("unable to create default secrets config: %w", err)
	}
	return SecretsCatalogerConfig{
		Patterns:     patterns,
		RevealValues: false,
		MaxFileSize:  1 * file.MB,
	}
}

func NewSecretsCataloger(config SecretsCatalogerConfig) (*SecretsCataloger, error) {
	return &SecretsCataloger{
		config: config,
	}, nil
}

func (i *SecretsCataloger) Catalog(resolver source.FileResolver) (map[source.Coordinates][]SearchResult, error) {
	results := make(map[source.Coordinates][]SearchResult)
	locations := allRegularFiles(resolver)
	stage, prog, secretsDiscovered := monitor.NewSecretsCatalogerMonitor(int64(len(locations)))
	for _, location := range locations {
		stage.Current = location.RealPath
		result, err := i.catalogLocation(resolver, location)
		if internal.IsErrPathPermission(err) {
			log.Debugf("secrets cataloger skipping - %+v", err)
			continue
		}

		if err != nil {
			return nil, err
		}
		if len(result) > 0 {
			secretsDiscovered.N += int64(len(result))
			results[location.Coordinates] = result
		}
		prog.N++
	}
	log.Debugf("secrets cataloger discovered %d secrets", secretsDiscovered.N)
	prog.SetCompleted()
	return results, nil
}

func (i *SecretsCataloger) catalogLocation(resolver source.FileResolver, location source.Location) ([]SearchResult, error) {
	metadata, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return nil, err
	}

	if metadata.Size == 0 {
		return nil, nil
	}

	if i.config.MaxFileSize > 0 && metadata.Size > i.config.MaxFileSize {
		return nil, nil
	}

	// TODO: in the future we can swap out search strategies here
	secrets, err := catalogLocationByLine(resolver, location, i.config.Patterns)
	if err != nil {
		return nil, internal.ErrPath{Context: "secrets-cataloger", Path: location.RealPath, Err: err}
	}

	if i.config.RevealValues {
		for idx, secret := range secrets {
			value, err := extractValue(resolver, location, secret.SeekPosition, secret.Length)
			if err != nil {
				return nil, err
			}
			secrets[idx].Value = value
		}
	}

	// sort by the start location of each secret as it appears in the location
	sort.SliceStable(secrets, func(i, j int) bool {
		return secrets[i].SeekPosition < secrets[j].SeekPosition
	})

	return secrets, nil
}

func extractValue(resolver source.FileResolver, location source.Location, start, length int64) (string, error) {
	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return "", fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	defer internal.CloseAndLogError(readCloser, location.VirtualPath)

	n, err := io.CopyN(ioutil.Discard, readCloser, start)
	if err != nil {
		return "", fmt.Errorf("unable to read contents for location=%q : %w", location, err)
	}
	if n != start {
		return "", fmt.Errorf("unexpected seek location for location=%q : %d != %d", location, n, start)
	}

	var buf bytes.Buffer
	n, err = io.CopyN(&buf, readCloser, length)
	if err != nil {
		return "", fmt.Errorf("unable to read secret value for location=%q : %w", location, err)
	}
	if n != length {
		return "", fmt.Errorf("unexpected secret length for location=%q : %d != %d", location, n, length)
	}

	return buf.String(), nil
}
