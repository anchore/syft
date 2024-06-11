package rust

type CargoToml struct {
	Package TomlPackage `toml:"package"`
}
type TomlPackage struct {
	License     string `toml:"license"`
	LicenseFile string `toml:"license"`
}
