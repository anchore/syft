module github.com/anchore/syft

go 1.16

require (
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d
	github.com/adrg/xdg v0.2.1
	github.com/alecthomas/jsonschema v0.0.0-20210301060011-54c507b6f074
	github.com/anchore/client-go v0.0.0-20210222170800-9c70f9b80bcf
	github.com/anchore/go-rpmdb v0.0.0-20210602151223-1f0f707a2894
	github.com/anchore/go-testutils v0.0.0-20200925183923-d5f45b0d3c04
	github.com/anchore/go-version v1.2.2-0.20200701162849-18adb9c92b9b
	github.com/anchore/stereoscope v0.0.0-20210817160504-0f4abc2a5a5a
	github.com/antihax/optional v1.0.0
	github.com/bmatcuk/doublestar/v2 v2.0.4
	github.com/docker/docker v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible
	github.com/dustin/go-humanize v1.0.0
	github.com/facebookincubator/nvdtools v0.1.4
	github.com/go-test/deep v1.0.7
	github.com/google/uuid v1.1.1
	github.com/gookit/color v1.2.7
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hashicorp/go-version v1.2.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.3.1
	github.com/olekukonko/tablewriter v0.0.4
	github.com/package-url/packageurl-go v0.1.0
	github.com/pelletier/go-toml v1.8.0
	github.com/pkg/profile v1.5.0
	github.com/scylladb/go-set v1.0.2
	github.com/sergi/go-diff v1.1.0
	github.com/sirupsen/logrus v1.6.0
	github.com/spdx/tools-golang v0.1.0
	github.com/spf13/afero v1.2.2
	github.com/spf13/cobra v1.0.1-0.20200909172742-8a63648dd905
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.7.0
	github.com/vifraa/gopom v0.1.0
	github.com/wagoodman/go-partybus v0.0.0-20210627031916-db1f5573bbc5
	github.com/wagoodman/go-progress v0.0.0-20200731105512-1020f39e6240
	github.com/wagoodman/jotframe v0.0.0-20200730190914-3517092dd163
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/mod v0.3.0
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/package-url/packageurl-go v0.1.0 => github.com/anchore/packageurl-go v0.1.0-fixed
