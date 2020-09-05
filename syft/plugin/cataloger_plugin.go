package plugin

import (
	"context"

	"github.com/anchore/syft/syft/cataloger"
	syftPluginGrpc "github.com/anchore/syft/syft/plugin/grpc"
	"github.com/anchore/syft/syft/plugin/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// integrity check
var _ plugin.GRPCPlugin = &CatalogerPlugin{}

// CatalogerPlugin is the implementation of plugin.Plugin that is served/consumed.
type CatalogerPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	Impl cataloger.Cataloger
}

func (p *CatalogerPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterCatalogerServer(s, syftPluginGrpc.NewCatalogServer(p.Impl, broker))
	return nil
}

func (p *CatalogerPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return syftPluginGrpc.NewCatalogerClient(proto.NewCatalogerClient(c), broker), nil
}
