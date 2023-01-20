module github.com/anchore/syft

go 1.18

require (
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d
	github.com/acobaugh/osrelease v0.1.0
	github.com/adrg/xdg v0.4.0
	github.com/anchore/go-macholibre v0.0.0-20220308212642-53e6d0aaf6fb
	github.com/anchore/go-testutils v0.0.0-20200925183923-d5f45b0d3c04
	github.com/anchore/go-version v1.2.2-0.20200701162849-18adb9c92b9b
	github.com/anchore/packageurl-go v0.1.1-0.20230104203445-02e0a6721501
	github.com/bmatcuk/doublestar/v4 v4.6.0
	github.com/dustin/go-humanize v1.0.0
	github.com/facebookincubator/nvdtools v0.1.4
	github.com/go-test/deep v1.1.0
	github.com/google/go-cmp v0.5.9
	github.com/google/uuid v1.3.0
	github.com/gookit/color v1.4.2
	github.com/hashicorp/go-multierror v1.1.1
	github.com/jinzhu/copier v0.3.2
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mholt/archiver/v3 v3.5.1
	github.com/microsoft/go-rustaudit v0.0.0-20220730194248-4b17361d90a5
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/mitchellh/mapstructure v1.5.0
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pelletier/go-toml v1.9.5
	// pinned to pull in 386 arch fix: https://github.com/scylladb/go-set/commit/cc7b2070d91ebf40d233207b633e28f5bd8f03a5
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e
	github.com/sergi/go-diff v1.3.1
	github.com/sirupsen/logrus v1.9.0
	github.com/spdx/tools-golang v0.3.1-0.20221108182156-8a01147e6342
	github.com/spf13/afero v1.9.3
	github.com/spf13/cobra v1.6.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.15.0
	github.com/stretchr/testify v1.8.1
	github.com/vifraa/gopom v0.2.1
	github.com/wagoodman/go-partybus v0.0.0-20210627031916-db1f5573bbc5
	github.com/wagoodman/go-progress v0.0.0-20200731105512-1020f39e6240
	github.com/wagoodman/jotframe v0.0.0-20211129225309-56b0d0a4aebb
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/mod v0.6.0
	golang.org/x/net v0.5.0
	golang.org/x/term v0.4.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/CycloneDX/cyclonedx-go v0.7.1-0.20221222100750-41a1ac565cce
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/anchore/go-logger v0.0.0-20220728155337-03b66a5207d8
	github.com/anchore/stereoscope v0.0.0-20221208011002-c5ff155d72f1
	github.com/docker/docker v20.10.20+incompatible
	github.com/google/go-containerregistry v0.12.1
	github.com/invopop/jsonschema v0.7.0
	github.com/knqyf263/go-rpmdb v0.0.0-20221030135625-4082a22221ce
	github.com/opencontainers/go-digest v1.0.0
	github.com/sassoftware/go-rpmutils v0.2.0
	github.com/vbatts/go-mtree v0.5.0
	golang.org/x/exp v0.0.0-20220823124025-807a23277127
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/DataDog/zstd v1.4.5 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/containerd/containerd v1.6.12 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.12.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/cli v20.10.20+incompatible // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.0 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/compress v1.15.11 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/logrusorgru/aurora v0.0.0-20200102142835-e9ef32dff381 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc2 // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.8.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/sylabs/sif/v2 v2.8.1 // indirect
	github.com/sylabs/squashfs v0.6.1 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xo/terminfo v0.0.0-20210125001918-ca9a967f8778 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	golang.org/x/tools v0.1.12 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/genproto v0.0.0-20221227171554-f9683d7f8bef // indirect
	google.golang.org/grpc v1.52.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	lukechampine.com/uint128 v1.1.1 // indirect
	modernc.org/cc/v3 v3.36.0 // indirect
	modernc.org/ccgo/v3 v3.16.6 // indirect
	modernc.org/libc v1.16.7 // indirect
	modernc.org/mathutil v1.4.1 // indirect
	modernc.org/memory v1.1.1 // indirect
	modernc.org/opt v0.1.1 // indirect
	modernc.org/sqlite v1.17.3 // indirect
	modernc.org/strutil v1.1.1 // indirect
	modernc.org/token v1.0.0 // indirect
)

require (
	// we are hinting brotli to latest due to warning when installing archiver v3:
	// go: warning: github.com/andybalholm/brotli@v1.0.1: retracted by module author: occasional panics and data corruption
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.1.0 // indirect
)

retract (
	v0.53.2
	v0.53.1 // Published accidentally with incorrect license in depdencies
)
