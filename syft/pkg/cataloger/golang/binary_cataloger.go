/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "go-module-binary-cataloger"

type Cataloger struct{}

// NewGoModuleBinaryCataloger returns a new Golang cataloger object.
func NewGoModuleBinaryCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return catalogerName
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm db installation.
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	fileMatches, err := resolver.FilesByMIMEType(internal.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return pkgs, nil, fmt.Errorf("failed to find bin by mime types: %w", err)
	}

	for _, location := range fileMatches {
		readerCloser, err := resolver.FileContentsByLocation(location)
		if err != nil {
			log.Warnf("golang cataloger: opening file: %v", err)
			continue
		}

		reader, err := getUnionReader(readerCloser)
		if err != nil {
			return nil, nil, err
		}

		mods, archs := scanFile(reader, location.RealPath)
		internal.CloseAndLogError(readerCloser, location.RealPath)

		for i, mod := range mods {
			pkgs = append(pkgs, buildGoPkgInfo(location, mod, archs[i])...)
		}
	}

	return pkgs, nil, nil
}

func getUnionReader(readerCloser io.ReadCloser) (unionReader, error) {
	reader, ok := readerCloser.(unionReader)
	if ok {
		return reader, nil
	}
	log.Debugf("golang cataloger: unable to use stereoscope file, reading entire contents")

	b, err := ioutil.ReadAll(readerCloser)
	if err != nil {
		return nil, fmt.Errorf("unable to read contents from go binary: %w", err)
	}

	bytesReader := bytes.NewReader(b)

	reader = struct {
		io.ReadCloser
		io.ReaderAt
		io.Seeker
	}{
		ReadCloser: io.NopCloser(bytesReader),
		ReaderAt:   bytesReader,
		Seeker:     bytesReader,
	}

	return reader, nil
}
