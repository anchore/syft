package plugin

import (
	"fmt"
	"github.com/hashicorp/go-hclog"
	"os"
	"os/exec"

	"github.com/hashicorp/go-plugin"
)

var versionedPlugins = map[int]plugin.PluginSet{
	1: {
		TypeCataloger.String(): &CatalogerPlugin{},
	},
}

type Plugin struct {
	Config       Config
	clientConfig plugin.ClientConfig
	client       *plugin.Client
}

// TODO: type should be in the name like with terraform "terraform-<TYPE>-<NAME>"

func NewPlugin(config Config) Plugin {
	cmd := exec.Command("sh", "-c", config.Command) //, config.Args...)
	cmd.Env = append(cmd.Env, config.Env...)

	//secureConfig := &plugin.SecureConfig{
	//	Checksum: config.Sha256,
	//	Hash:     sha256.New(),
	//}

	// TODO: temp?
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   config.Name,
		Level:  hclog.Trace,
		Output: os.Stderr,
	})

	clientConfig := plugin.ClientConfig{
		HandshakeConfig:  config.Type.HandshakeConfig(),
		VersionedPlugins: versionedPlugins,
		//SecureConfig:     secureConfig,
		Cmd:    cmd,
		Logger: logger,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
	}

	return Plugin{
		Config:       config,
		clientConfig: clientConfig,
	}
}

func (p Plugin) Start() (interface{}, error) {
	if p.client != nil {
		return nil, fmt.Errorf("plugin already started")
	}

	// start the plugin in a sub process
	p.client = plugin.NewClient(&p.clientConfig)

	// connect to the sub process via RPC
	rpcClient, err := p.client.Client()
	if err != nil {
		return nil, err
	}

	// fetch the plugin object meeting the requested interface
	raw, err := rpcClient.Dispense(p.Config.Type.String())
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func (p Plugin) Stop() error {
	if p.client == nil {
		return fmt.Errorf("plugin has not been started")
	}
	p.client.Kill()
	return nil
}
