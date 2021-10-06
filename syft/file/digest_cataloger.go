package file

import (
	"crypto"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

type DigestsCataloger struct {
	hashes []crypto.Hash
}

func NewDigestsCataloger(hashes []crypto.Hash) (*DigestsCataloger, error) {
	return &DigestsCataloger{
		hashes: hashes,
	}, nil
}

func (i *DigestsCataloger) Catalog(resolver source.FileResolver) (map[source.Location][]Digest, error) {
	results := make(map[source.Location][]Digest)
	var locations []source.Location
	for location := range resolver.AllLocations() {
		locations = append(locations, location)
	}
	stage, prog := digestsCatalogingProgress(int64(len(locations)))
	for _, location := range locations {
		stage.Current = location.RealPath
		result, err := i.catalogLocation(resolver, location)
		if internal.IsErrPathPermission(err) {
			log.Debugf("file digests cataloger skipping - %+v", err)
			continue
		}

		if err != nil {
			return nil, err
		}
		prog.N++
		results[location] = result
	}
	log.Debugf("file digests cataloger processed %d files", prog.N)
	prog.SetCompleted()
	return results, nil
}

func (i *DigestsCataloger) catalogLocation(resolver source.FileResolver, location source.Location) ([]Digest, error) {
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contentReader, location.VirtualPath)

	// create a set of hasher objects tied together with a single writer to feed content into
	hashers := make([]hash.Hash, len(i.hashes))
	writers := make([]io.Writer, len(i.hashes))
	for idx, hashObj := range i.hashes {
		hashers[idx] = hashObj.New()
		writers[idx] = hashers[idx]
	}

	size, err := io.Copy(io.MultiWriter(writers...), contentReader)
	if err != nil {
		return nil, internal.PathError{Path: location.RealPath, Err: err}
	}

	if size == 0 {
		return make([]Digest, 0), nil
	}

	result := make([]Digest, len(i.hashes))
	// only capture digests when there is content. It is important to do this based on SIZE and not
	// FILE TYPE. The reasoning is that it is possible for a tar to be crafted with a header-only
	// file type but a body is still allowed.
	for idx, hasher := range hashers {
		result[idx] = Digest{
			Algorithm: DigestAlgorithmName(i.hashes[idx]),
			Value:     fmt.Sprintf("%+x", hasher.Sum(nil)),
		}
	}

	return result, nil
}

func DigestAlgorithmName(hash crypto.Hash) string {
	return CleanDigestAlgorithmName(hash.String())
}

func CleanDigestAlgorithmName(name string) string {
	lower := strings.ToLower(name)
	return strings.ReplaceAll(lower, "-", "")
}

func digestsCatalogingProgress(locations int64) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := &progress.Manual{
		Total: locations,
	}

	bus.Publish(partybus.Event{
		Type: event.FileDigestsCatalogerStarted,
		Value: struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		},
	})

	return stage, prog
}
