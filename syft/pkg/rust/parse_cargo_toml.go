package rust

type CargoToml struct {
	Package TomlPackage `toml:"package"`
}
type TomlPackage struct {
	Description string `toml:"description"`
	Homepage    string `toml:"homepage"`
	License     string `toml:"license"`
	LicenseFile string `toml:"license-file"`
}
