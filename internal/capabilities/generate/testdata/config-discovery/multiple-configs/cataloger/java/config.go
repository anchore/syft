package java

// ArchiveCatalogerConfig contains configuration for the java archive cataloger
type ArchiveCatalogerConfig struct {
	// include archive contents in catalog
	// app-config: java.use-network
	UseNetwork bool
}
