package grpc

import (
	"context"
	"github.com/anchore/syft/internal/log"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/plugin/proto"
	"github.com/anchore/syft/syft/scope"
)

type FileResolverServer struct {
	Impl scope.FileResolver
}

func (m *FileResolverServer) FilesByPath(ctx context.Context, req *proto.FileResolverRequest) (resp *proto.FileResolverResponse, err error) {
	var paths []file.Path
	for _, p := range req.Paths {
		paths = append(paths, file.Path(p))
	}
	r, err := m.Impl.FilesByPath(paths...)
	if err != nil {
		return nil, err
	}

	var refs []*proto.FileReference
	for _, ref := range r {
		refs = append(refs, &proto.FileReference{
			Id:   int64(ref.ID()),
			Path: string(ref.Path),
		})
	}

	return &proto.FileResolverResponse{
		Files: refs,
	}, nil
}

func (m *FileResolverServer) FilesByGlob(ctx context.Context, req *proto.FileResolverRequest) (resp *proto.FileResolverResponse, err error) {
	log.Debugf("FilesByGlob Request: %+v", req)

	r, err := m.Impl.FilesByGlob(req.Paths...)
	if err != nil {
		return nil, err
	}

	log.Debugf("FilesByGlob Result: %+v", r)

	var refs []*proto.FileReference
	for _, ref := range r {
		refs = append(refs, &proto.FileReference{
			Id:   int64(ref.ID()),
			Path: string(ref.Path),
		})
	}

	return &proto.FileResolverResponse{
		Files: refs,
	}, nil
}
