package rust

type cargoToml struct {
	Package tomlPackage `toml:"package"`
}
type tomlPackage struct {
	License     string `toml:"license"`
	LicenseFile string `toml:"license-file"`
}
