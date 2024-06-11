package rust

type CargoToml struct {
	Package `toml:"package"`
}
type Package struct {
	License     string `toml:"license"`
	LicenseFile string `toml:"license"`
}
