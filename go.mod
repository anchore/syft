module github.com/anchore/syft

go 1.14

require (
	github.com/Microsoft/hcsshim v0.8.10 // indirect
	github.com/adrg/xdg v0.2.1
	github.com/anchore/go-rpmdb v0.0.0-20200811175839-cbc751c28e8e
	github.com/anchore/go-testutils v0.0.0-20200924130829-c7fdedf242b7
	github.com/anchore/go-version v1.2.2-0.20200701162849-18adb9c92b9b
	github.com/anchore/stereoscope v0.0.0-20200922191919-df2d5de22d9d
	github.com/bmatcuk/doublestar v1.3.1
	github.com/containerd/continuity v0.0.0-20200710164510-efbc4488d8fe // indirect
	github.com/docker/docker v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible
	github.com/dustin/go-humanize v1.0.0
	github.com/go-test/deep v1.0.6
	github.com/google/uuid v1.1.1
	github.com/gookit/color v1.2.7
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hashicorp/go-version v1.2.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.3.1
	github.com/olekukonko/tablewriter v0.0.4
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/package-url/packageurl-go v0.1.0
	github.com/pelletier/go-toml v1.8.0
	github.com/rogpeppe/go-internal v1.5.2
	github.com/sergi/go-diff v1.1.0
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/afero v1.2.2
	github.com/spf13/cobra v1.0.1-0.20200909172742-8a63648dd905
	github.com/spf13/viper v1.7.0
	github.com/wagoodman/go-partybus v0.0.0-20200526224238-eb215533f07d
	github.com/wagoodman/go-progress v0.0.0-20200731105512-1020f39e6240
	github.com/wagoodman/jotframe v0.0.0-20200730190914-3517092dd163
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/anchore/stereoscope => ../stereoscope

replace github.com/anchore/go-testutils => ../go-testutils
