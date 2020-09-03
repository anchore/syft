package grpc

import (
	"context"
	"io"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/plugin/proto"
	"github.com/hashicorp/go-plugin"
)

type CatalogerServer struct {
	Impl   cataloger.Cataloger
	broker *plugin.GRPCBroker
}

func NewCatalogServer(impl cataloger.Cataloger, broker *plugin.GRPCBroker) *CatalogerServer {
	return &CatalogerServer{
		Impl:   impl,
		broker: broker,
	}
}

func (s *CatalogerServer) Name(ctx context.Context, req *proto.Empty) (*proto.NameResponse, error) {
	name := s.Impl.Name()
	return &proto.NameResponse{
		Name: name,
	}, nil
}

func (s *CatalogerServer) SelectFiles(ctx context.Context, req *proto.SelectFilesRequest) (*proto.SelectFilesResponse, error) {
	conn, err := s.broker.Dial(req.FileResolverBrokerId)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	fileResolverClient := &FileResolverClient{proto.NewFileResolverClient(conn)}

	fileRefs := s.Impl.SelectFiles(fileResolverClient)

	var refs []*proto.FileReference
	for _, ref := range fileRefs {
		refs = append(refs, &proto.FileReference{
			Id:   int64(ref.ID()),
			Path: string(ref.Path),
		})
	}

	return &proto.SelectFilesResponse{
		Files: refs,
	}, nil
}

func (s *CatalogerServer) Catalog(ctx context.Context, req *proto.CatalogRequest) (*proto.CatalogResponse, error) {
	contents := make(map[file.Reference]io.Reader)
	for _, f := range req.Contents {
		contents[file.NewFileReferenceWithID(file.Path(f.Path), uint64(f.Id))] = strings.NewReader(f.Contents)
	}
	packages, err := s.Impl.Catalog(contents)
	if err != nil {
		return nil, err
	}

	var results []proto.Package
	for _, p := range packages {
		var sources []*proto.FileReference
		for _, s := range p.Source {
			sources = append(sources, &proto.FileReference{
				Id:   int64(s.ID()),
				Path: string(s.Path),
			})
		}

		var metadata map[string]string
		if v, ok := p.Metadata.(map[string]string); ok {
			metadata = v
		}

		// TODO: this is potentially brittle
		results = append(results, proto.Package{
			Name:     p.Name,
			Version:  p.Version,
			FoundBy:  p.FoundBy,
			Source:   sources,
			Licenses: p.Licenses,
			Language: uint64(p.Language),
			Type:     string(p.Type),
			// TODO: metadata needs to be more thoroughly thought through
			Metadata: metadata,
		})
	}

	return &proto.CatalogResponse{
		Package: nil,
	}, nil
}
