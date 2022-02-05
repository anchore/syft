module github.com/anchore/syft

go 1.16

require (
	github.com/CycloneDX/cyclonedx-go v0.4.0
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d
	github.com/acobaugh/osrelease v0.1.0
	github.com/adrg/xdg v0.2.1
	github.com/alecthomas/jsonschema v0.0.0-20210301060011-54c507b6f074
	github.com/anchore/client-go v0.0.0-20210222170800-9c70f9b80bcf
	github.com/anchore/go-logger v0.0.0
	github.com/anchore/go-rpmdb v0.0.0-20210914181456-a9c52348da63
	github.com/anchore/go-testutils v0.0.0-20200925183923-d5f45b0d3c04
	github.com/anchore/go-version v1.2.2-0.20200701162849-18adb9c92b9b
	github.com/anchore/packageurl-go v0.0.0-20210922164639-b3fa992ebd29
	github.com/anchore/stereoscope v0.0.0-20220201190559-f162f1e96f45
	// we are hinting brotli to latest due to warning when installing archiver v3:
	// go: warning: github.com/andybalholm/brotli@v1.0.1: retracted by module author: occasional panics and data corruption
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/antihax/optional v1.0.0
	github.com/bmatcuk/doublestar/v4 v4.0.2
	github.com/containerd/containerd v1.5.9 // indirect
	github.com/docker/docker v20.10.12+incompatible
	github.com/dustin/go-humanize v1.0.0
	github.com/facebookincubator/nvdtools v0.1.4
	github.com/go-test/deep v1.0.8
	github.com/google/go-cmp v0.5.6
	github.com/google/uuid v1.2.0
	github.com/gookit/color v1.2.7
	github.com/hashicorp/go-multierror v1.1.0
	github.com/jinzhu/copier v0.3.2
	github.com/mholt/archiver/v3 v3.5.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/mitchellh/mapstructure v1.4.1
	github.com/olekukonko/tablewriter v0.0.4
	github.com/pelletier/go-toml v1.9.3
	github.com/pkg/profile v1.5.0
	github.com/scylladb/go-set v1.0.2
	github.com/sergi/go-diff v1.1.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spdx/tools-golang v0.1.0
	github.com/spf13/afero v1.6.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/vifraa/gopom v0.1.0
	github.com/wagoodman/go-partybus v0.0.0-20210627031916-db1f5573bbc5
	github.com/wagoodman/go-progress v0.0.0-20200731105512-1020f39e6240
	github.com/wagoodman/jotframe v0.0.0-20211129225309-56b0d0a4aebb
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/mod v0.4.2
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/anchore/stereoscope => ../stereoscope

replace github.com/anchore/go-logger => ../go-logger
