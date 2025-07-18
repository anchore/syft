package cpp

type CatalogerConfig struct {
	VcpkgAllowGitClone bool
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		// syft defaults to not sending requests over the network. You must opt in
		VcpkgAllowGitClone: false,
	}
}

func (c CatalogerConfig) WithVcpkgAllowGitClone(input bool) CatalogerConfig {
	c.VcpkgAllowGitClone = input
	return c
}
