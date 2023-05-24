package secrets

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
	internal2 "github.com/anchore/syft/syft/file/cataloger/internal"
)

var DefaultSecretsPatterns = map[string]string{
	"aws-access-key":     `(?i)aws_access_key_id["'=:\s]*?(?P<value>(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`,
	"aws-secret-key":     `(?i)aws_secret_access_key["'=:\s]*?(?P<value>[0-9a-zA-Z/+]{40})`,
	"pem-private-key":    `-----BEGIN (\S+ )?PRIVATE KEY(\sBLOCK)?-----((?P<value>(\n.*?)+)-----END (\S+ )?PRIVATE KEY(\sBLOCK)?-----)?`,
	"docker-config-auth": `"auths"((.*\n)*.*?"auth"\s*:\s*"(?P<value>[^"]+)")?`,
	"generic-api-key":    `(?i)api(-|_)?key["'=:\s]*?(?P<value>[A-Z0-9]{20,60})["']?(\s|$)`,
}

// Deprecated: will be removed in syft v1.0.0
type Cataloger struct {
	patterns           map[string]*regexp.Regexp
	revealValues       bool
	skipFilesAboveSize int64
}

// Deprecated: will be removed in syft v1.0.0
func NewCataloger(patterns map[string]*regexp.Regexp, revealValues bool, maxFileSize int64) (*Cataloger, error) {
	return &Cataloger{
		patterns:           patterns,
		revealValues:       revealValues,
		skipFilesAboveSize: maxFileSize,
	}, nil
}

func (i *Cataloger) Catalog(resolver file.Resolver) (map[file.Coordinates][]file.SearchResult, error) {
	results := make(map[file.Coordinates][]file.SearchResult)
	locations := internal2.AllRegularFiles(resolver)
	stage, prog, secretsDiscovered := secretsCatalogingProgress(int64(len(locations)))
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
			secretsDiscovered.Add(int64(len(result)))
			results[location.Coordinates] = result
		}
		prog.Increment()
	}
	log.Debugf("secrets cataloger discovered %d secrets", secretsDiscovered.Current())
	prog.SetCompleted()
	return results, nil
}

func (i *Cataloger) catalogLocation(resolver file.Resolver, location file.Location) ([]file.SearchResult, error) {
	metadata, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return nil, err
	}

	if metadata.Size() == 0 {
		return nil, nil
	}

	if i.skipFilesAboveSize > 0 && metadata.Size() > i.skipFilesAboveSize {
		return nil, nil
	}

	// TODO: in the future we can swap out search strategies here
	secrets, err := catalogLocationByLine(resolver, location, i.patterns)
	if err != nil {
		return nil, internal.ErrPath{Context: "secrets-cataloger", Path: location.RealPath, Err: err}
	}

	if i.revealValues {
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

func extractValue(resolver file.Resolver, location file.Location, start, length int64) (string, error) {
	readCloser, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return "", fmt.Errorf("unable to fetch reader for location=%q : %w", location, err)
	}
	defer internal.CloseAndLogError(readCloser, location.VirtualPath)

	n, err := io.CopyN(io.Discard, readCloser, start)
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

type Monitor struct {
	progress.Stager
	SecretsDiscovered progress.Monitorable
	progress.Progressable
}

func secretsCatalogingProgress(locations int64) (*progress.Stage, *progress.Manual, *progress.Manual) {
	stage := &progress.Stage{}
	secretsDiscovered := &progress.Manual{}
	prog := progress.NewManual(locations)

	bus.Publish(partybus.Event{
		Type:   event.SecretsCatalogerStarted,
		Source: secretsDiscovered,
		Value: Monitor{
			Stager:            progress.Stager(stage),
			SecretsDiscovered: secretsDiscovered,
			Progressable:      prog,
		},
	})

	return stage, prog, secretsDiscovered
}
