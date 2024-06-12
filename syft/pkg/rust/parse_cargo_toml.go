package rust

type CargoToml struct {
	Package TomlPackage `toml:"package"`
}
type TomlPackage struct {
	Description string `toml:"description"`
	License     string `toml:"license"`
	LicenseFile string `toml:"license-file"`
}
