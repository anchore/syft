package grpc

import (
	"context"
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloger"
	"io"
	"io/ioutil"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/plugin/proto"
	"github.com/anchore/syft/syft/scope"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

var _ cataloger.Cataloger = &CatalogerClient{}

type CatalogerClient struct {
	broker *plugin.GRPCBroker
	client proto.CatalogerClient
}

func NewCatalogerClient(client proto.CatalogerClient, broker *plugin.GRPCBroker) *CatalogerClient {
	return &CatalogerClient{
		broker: broker,
		client: client,
	}
}

func (c *CatalogerClient) Name() string {
	resp, err := c.client.Name(context.Background(), &proto.Empty{})
	if err != nil {
		return fmt.Sprintf("error (%s)", err.Error())
	}

	return resp.Name
}

func (c *CatalogerClient) SelectFiles(resolver scope.FileResolver) []file.Reference {
	fileResolverServer := &FileResolverServer{Impl: resolver}

	var s *grpc.Server
	serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
		s = grpc.NewServer(opts...)
		proto.RegisterFileResolverServer(s, fileResolverServer)

		return s
	}

	brokerID := c.broker.NextId()
	go c.broker.AcceptAndServe(brokerID, serverFunc)

	resp, err := c.client.SelectFiles(context.Background(), &proto.SelectFilesRequest{
		FileResolverBrokerId: brokerID,
	})

	log.Debugf("Select Files Response: %+v", resp)

	if err != nil {
		// TODO: nope
		panic(err)
	}

	s.Stop()

	var result []file.Reference
	for _, f := range resp.Files {
		result = append(result, file.NewFileReferenceWithID(file.Path(f.Path), uint64(f.Id)))
	}

	return result
}

func (c *CatalogerClient) Catalog(contents map[file.Reference]io.Reader) ([]pkg.Package, error) {
	var fileRefContents []*proto.FileReferenceContents
	for ref, reader := range contents {
		readerContents, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("could not read %+v contents: %+v", ref, err)
		}
		fileRefContents = append(fileRefContents, &proto.FileReferenceContents{
			Id:       int64(ref.ID()),
			Path:     string(ref.Path),
			Contents: string(readerContents),
		})
	}
	resp, err := c.client.Catalog(context.Background(), &proto.CatalogRequest{
		Contents: fileRefContents,
	})
	if err != nil {
		return nil, err
	}

	var result []pkg.Package
	for _, p := range resp.Package {
		if p != nil {
			var sources []file.Reference
			for _, s := range p.Source {
				sources = append(sources, file.NewFileReferenceWithID(file.Path(s.Path), uint64(s.Id)))
			}
			// TODO: this is potentially brittle
			result = append(result, pkg.Package{
				Name:     p.Name,
				Version:  p.Version,
				FoundBy:  p.FoundBy,
				Source:   sources,
				Licenses: p.Licenses,
				Language: pkg.Language(p.Language),
				Type:     pkg.Type(p.Type),
				Metadata: p.Metadata,
			})
		}
	}

	return result, nil
}
