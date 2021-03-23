package config

// CliOnlyOptions are options that are in the application config in memory, but are only exposed via CLI switches (not from unmarshaling a config file)
type CliOnlyOptions struct {
	ConfigPath string // -c. where the read config is on disk
	Verbosity  int    // -v or -vv , controlling which UI (ETUI vs logging) and what the log level should be
}
