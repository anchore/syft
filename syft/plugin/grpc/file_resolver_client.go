package grpc

import (
	"context"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/plugin/proto"
)

type FileResolverClient struct{ client proto.FileResolverClient }

func (m *FileResolverClient) FilesByPath(paths ...file.Path) ([]file.Reference, error) {
	var pathStrs []string
	for _, p := range paths {
		pathStrs = append(pathStrs, string(p))
	}
	resp, err := m.client.FilesByPath(context.Background(), &proto.FileResolverRequest{
		Paths: pathStrs,
	})
	if err != nil {
		return nil, err
	}

	var result []file.Reference
	for _, ref := range resp.Files {
		result = append(result, file.NewFileReferenceWithID(file.Path(ref.Path), uint64(ref.Id)))
	}

	return result, err
}

func (m *FileResolverClient) FilesByGlob(patterns ...string) ([]file.Reference, error) {
	resp, err := m.client.FilesByGlob(context.Background(), &proto.FileResolverRequest{
		Paths: patterns,
	})
	if err != nil {
		return nil, err
	}

	log.Debugf("FilesByGlob Response: %+v", resp)

	var result []file.Reference
	for _, ref := range resp.Files {
		result = append(result, file.NewFileReferenceWithID(file.Path(ref.Path), uint64(ref.Id)))
	}

	return result, err
}
