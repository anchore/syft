package file

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"sort"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/source"
	"github.com/bmatcuk/doublestar/v2"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

const readFullFileThreshold = 50 * file.MB

var DefaultSecretsPatterns = map[string]string{
	"aws-access-key":     `(?i)aws_access_key_id["'=:\s]*(?P<value>(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`,
	"aws-secret-key":     `(?i)aws_secret_access_key["'=:\s]*(?P<value>[0-9a-zA-Z/+]{40})`,
	"pem-private-key":    `-----BEGIN (\S+ )?PRIVATE KEY(\sBLOCK)?-----((\n.*)+-----END (\S+ )?PRIVATE KEY(\sBLOCK)?-----)?`,
	"docker-config-auth": `(?i)"auths"(.*\n)*.*"auth"\s*:\s*"(?P<value>[^"]+)"`,
}

type secretsSearchStrategy func(source.FileResolver, source.Location, map[string]*regexp.Regexp) ([]Secret, error)

func GenerateSecretPatterns(basePatterns map[string]string, additionalPatterns map[string]string, excludePatternNames []string) (map[string]*regexp.Regexp, error) {
	var regexObjs = make(map[string]*regexp.Regexp)
	var errs error

	addFn := func(name, pattern string) {
		obj, err := regexp.Compile(`(?m)` + pattern)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("unable to parse %q regular expression: %w", name, err))
		}
		regexObjs[name] = obj
	}

	matchesExclusion := func(name string) bool {
		for _, exclude := range excludePatternNames {
			matches, err := doublestar.Match(exclude, name)
			if err != nil {
				return false
			}
			return matches
		}
		return false
	}

	// add all base cases... unless that base case was asked to be excluded
	for name, pattern := range basePatterns {
		if !matchesExclusion(name) {
			addFn(name, pattern)
		}
	}

	// add all additional cases
	for name, pattern := range additionalPatterns {
		addFn(name, pattern)
	}

	if errs != nil {
		return nil, errs
	}

	return regexObjs, nil
}

type SecretsCataloger struct {
	patterns           map[string]*regexp.Regexp
	revealValues       bool
	skipFilesAboveSize int64
}

func NewSecretsCataloger(patterns map[string]*regexp.Regexp, revealValues bool, maxFileSize int64) (*SecretsCataloger, error) {
	return &SecretsCataloger{
		patterns:           patterns,
		revealValues:       revealValues,
		skipFilesAboveSize: maxFileSize,
	}, nil
}

func (i *SecretsCataloger) Catalog(resolver source.FileResolver) (map[source.Location][]Secret, error) {
	results := make(map[source.Location][]Secret)
	var locations []source.Location
	for location := range resolver.AllLocations() {
		locations = append(locations, location)
	}
	stage, prog, secretsDiscovered := secretsCatalogingProgress(int64(len(locations)))
	for _, location := range locations {
		stage.Current = location.RealPath
		result, err := i.catalogLocation(resolver, location)
		if err != nil {
			return nil, err
		}
		if len(result) > 0 {
			secretsDiscovered.N += int64(len(result))
			results[location] = result
		}
		prog.N++
	}
	prog.SetCompleted()
	return results, nil
}

func (i *SecretsCataloger) catalogLocation(resolver source.FileResolver, location source.Location) ([]Secret, error) {
	metadata, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return nil, err
	}

	if i.skipFilesAboveSize > 0 && metadata.Size > i.skipFilesAboveSize {
		return nil, nil
	}

	strategy, err := selectSearchStrategy(resolver, location)
	if err != nil {
		return nil, err
	}

	secrets, err := strategy(resolver, location, i.patterns)
	if err != nil {
		return nil, err
	}

	if i.revealValues {
		for idx, secret := range secrets {
			value, err := extractValue(resolver, location, secret.Position, secret.Length)
			if err != nil {
				return nil, err
			}
			secrets[idx].Value = value
		}
	}

	// sort by the start location of each secret as it appears in the location
	sort.SliceStable(secrets, func(i, j int) bool {
		return secrets[i].Position < secrets[j].Position
	})

	return secrets, nil
}

func selectSearchStrategy(resolver source.FileResolver, location source.Location) (secretsSearchStrategy, error) {
	metadata, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return nil, err
	}

	if metadata.Size > readFullFileThreshold {
		return catalogLocationByLine, nil
	}
	return catalogLocationFullyInMemory, nil
}

func extractValue(resolver source.FileResolver, location source.Location, start, length int64) (string, error) {
	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return "", fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	defer readCloser.Close()

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

type SecretsMonitor struct {
	progress.Stager
	SecretsDiscovered progress.Monitorable
	progress.Progressable
}

func secretsCatalogingProgress(locations int64) (*progress.Stage, *progress.Manual, *progress.Manual) {
	stage := &progress.Stage{}
	secretsDiscovered := &progress.Manual{}
	prog := &progress.Manual{
		Total: locations,
	}

	bus.Publish(partybus.Event{
		Type:   event.SecretsCatalogerStarted,
		Source: secretsDiscovered,
		Value: SecretsMonitor{
			Stager:            progress.Stager(stage),
			SecretsDiscovered: secretsDiscovered,
			Progressable:      prog,
		},
	})

	return stage, prog, secretsDiscovered
}
