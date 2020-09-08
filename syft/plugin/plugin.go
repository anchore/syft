package plugin

import (
	"crypto/sha256"
	"fmt"
	"os/exec"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/logger"
	"github.com/hashicorp/go-hclog"
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
	//cmd := exec.Command("sh", "-c", config.Command) //, config.Args...)
	cmd := exec.Command(config.Command)
	cmd.Env = append(cmd.Env, config.Env...)

	var secureConfig *plugin.SecureConfig
	if len(config.Sha256) > 0 {
		secureConfig = &plugin.SecureConfig{
			Checksum: config.Sha256,
			Hash:     sha256.New(),
		}
	}

	var pluginLogger hclog.Logger
	if logrusLogger, ok := log.Log.(*logger.LogrusLogger); ok {
		pluginLogger = logger.NewLogrusHCLogAdapter(logrusLogger.Logger, map[string]interface{}{"plugin": config.Name})
	} else {
		// TODO: this does not fully map features, thus logging will be awkward
		// TODO: find a better way to map loggers (expand our interface?)
		pluginLogger = logger.NewLoggerHCLogAdapter(log.Log)
	}

	clientConfig := plugin.ClientConfig{
		HandshakeConfig:  config.Type.HandshakeConfig(),
		VersionedPlugins: versionedPlugins,
		SecureConfig:     secureConfig,
		Cmd:              cmd,
		Logger:           pluginLogger,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
	}

	return Plugin{
		Config:       config,
		clientConfig: clientConfig,
	}
}

func (p *Plugin) Start() (interface{}, error) {
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

func (p *Plugin) Stop() error {
	if p.client == nil {
		return fmt.Errorf("plugin has not been started")
	}
	p.client.Kill()
	return nil
}
