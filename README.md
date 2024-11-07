<p align="center">
    <img src="https://user-images.githubusercontent.com/5199289/136844524-1527b09f-c5cb-4aa9-be54-5aa92a6086c1.png" width="271" alt="Cute pink owl syft logo">
</p>

# Syft

**A CLI tool and Go library for generating a Software Bill of Materials (SBOM) from container images and filesystems. Exceptional for vulnerability detection when used with a scanner like [Grype](https://github.com/anchore/grype).**

<p align="center">
 &nbsp;<a href="https://github.com/anchore/syft/actions/workflows/validations.yaml" target="_blank"><img alt="Validations" src="https://github.com/anchore/syft/actions/workflows/validations.yaml/badge.svg"></a>&nbsp;
 &nbsp;<a href="https://goreportcard.com/report/github.com/anchore/syft" target="_blank"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/anchore/syft"></a>&nbsp;
 &nbsp;<a href="https://github.com/anchore/syft/releases/latest" target="_blank"><img alt="GitHub release" src="https://img.shields.io/github/release/anchore/syft.svg"></a>&nbsp;
 &nbsp;<a href="https://github.com/anchore/syft" target="_blank"><img alt="GitHub go.mod Go version" src="https://img.shields.io/github/go-mod/go-version/anchore/syft.svg"></a>&nbsp;
 &nbsp;<a href="" target="_blank"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"></a>&nbsp;
 &nbsp;<a href="https://anchore.com/discourse" target="_blank"><img alt="Join our Discourse" src="https://img.shields.io/badge/Discourse-Join-blue?logo=discourse"/></a>&nbsp;
 &nbsp;<a rel="me" href="https://fosstodon.org/@syft"><img alt="Follow on Mastodon" src="https://img.shields.io/badge/Mastodon-Follow-blue?logoColor=white&logo=mastodon"/></a>&nbsp;
</p>

![syft-demo](https://user-images.githubusercontent.com/590471/90277200-2a253000-de33-11ea-893f-32c219eea11a.gif)

## Introduction

Syft is a powerful and easy-to-use open-source tool for generating Software Bill of Materials (SBOMs) for container images and filesystems. It provides detailed visibility into the packages and dependencies in your software, helping you manage vulnerabilities, license compliance, and software supply chain security.

Syft development is sponsored by [Anchore](https://anchore.com/), and is released under the [Apache-2.0 License](https://github.com/anchore/syft?tab=Apache-2.0-1-ov-file). For commercial support options with Syft or Grype, please [contact Anchore](https://get.anchore.com/contact/).

## Features
- Generates SBOMs for container images, filesystems, archives, and more to discover packages and libraries
- Supports OCI, Docker and [Singularity](https://github.com/sylabs/singularity) image formats
- Linux distribution identification
- Works seamlessly with [Grype](https://github.com/anchore/grype) (a fast, modern vulnerability scanner)
- Able to create signed SBOM attestations using the [in-toto specification](https://github.com/in-toto/attestation/blob/main/spec/README.md)
- Convert between SBOM formats, such as CycloneDX, SPDX, and Syft's own format.

## Installation

Syft binaries are provided for Linux, macOS and Windows.

### Recommended
> ```bash 
> curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
> ```

Install script options:
-	`-b`: Specify a custom installation directory (defaults to `./bin`)
-	`-d`: More verbose logging levels (`-d` for debug, `-dd` for trace)
-	`-v`: Verify the signature of the downloaded artifact before installation (requires [`cosign`](https://github.com/sigstore/cosign) to be installed)

### Homebrew
```bash
brew install syft
```

### Scoop

```powershell
scoop install syft
```

### Chocolatey

The chocolatey distribution of Syft is community-maintained and not distributed by the Anchore team

```powershell
choco install syft -y
```

### Nix

**Note**: Nix packaging of Syft is [community maintained](https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/admin/syft/default.nix). Syft is available in the [stable channel](https://wiki.nixos.org/wiki/Nix_channels#The_official_channels) since NixOS `22.05`.

```bash
nix-env -i syft
```

... or, just try it out in an ephemeral nix shell:

```bash
nix-shell -p syft
```

## Getting started

### SBOM

To generate an SBOM for a container image:

```bash
syft <image>
```

The above output includes only software that is visible in the container (i.e., the squashed representation of the image). To include software from all image layers in the SBOM, regardless of its presence in the final image, provide `--scope all-layers`:

```bash
syft <image> --scope all-layers
```

### Output formats

The output format for Syft is configurable as well using the `-o` (or `--output`) option:

```
syft <image> -o <format>
```

Where the `formats` available are:
- `syft-json`: Use this to get as much information out of Syft as possible!
- `syft-text`: A row-oriented, human-and-machine-friendly output.
- `cyclonedx-xml`: A XML report conforming to the [CycloneDX 1.6 specification](https://cyclonedx.org/specification/overview/).
- `cyclonedx-xml@1.5`: A XML report conforming to the [CycloneDX 1.5 specification](https://cyclonedx.org/specification/overview/).
- `cyclonedx-json`: A JSON report conforming to the [CycloneDX 1.6 specification](https://cyclonedx.org/specification/overview/).
- `cyclonedx-json@1.5`: A JSON report conforming to the [CycloneDX 1.5 specification](https://cyclonedx.org/specification/overview/).
- `spdx-tag-value`: A tag-value formatted report conforming to the [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/).
- `spdx-tag-value@2.2`: A tag-value formatted report conforming to the [SPDX 2.2 specification](https://spdx.github.io/spdx-spec/v2.2.2/).
- `spdx-json`: A JSON report conforming to the [SPDX 2.3 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json).
- `spdx-json@2.2`: A JSON report conforming to the [SPDX 2.2 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.2/schemas/spdx-schema.json).
- `github-json`: A JSON report conforming to GitHub's dependency snapshot format.
- `syft-table`: A columnar summary (default).
- `template`: Lets the user specify the output format. See ["Using templates"](#using-templates) below.

Note that flags using the @<version> can be used for earlier versions of each specification as well.

### Supported Ecosystems

- Alpine (apk)
- C (conan)
- C++ (conan)
- Dart (pubs)
- Debian (dpkg)
- Dotnet (deps.json)
- Objective-C (cocoapods)
- Elixir (mix)
- Erlang (rebar3)
- Go (go.mod, Go binaries)
- Haskell (cabal, stack)
- Java (jar, ear, war, par, sar, nar, native-image)
- JavaScript (npm, yarn)
- Jenkins Plugins (jpi, hpi)
- Linux kernel archives (vmlinz)
- Linux kernel modules (ko)
- Nix (outputs in /nix/store)
- PHP (composer)
- Python (wheel, egg, poetry, requirements.txt)
- Red Hat (rpm)
- Ruby (gem)
- Rust (cargo.lock)
- Swift (cocoapods, swift-package-manager)
- Wordpress plugins

## Documentation

Our [wiki](https://github.com/anchore/syft/wiki) contains further details on the following topics:

* [Supported Sources](https://github.com/anchore/syft/wiki/supported-sources)
* [File Selection](https://github.com/anchore/syft/wiki/file-selection)
* [Excluding file paths](https://github.com/anchore/syft/wiki/excluding-file-paths)
* [Output formats](https://github.com/anchore/syft/wiki/output-formats)
* [Package Cataloger Selection](https://github.com/anchore/syft/wiki/package-cataloger-selection) 
  * [Concepts](https://github.com/anchore/syft/wiki/package-cataloger-selection#concepts)
  * [Examples](https://github.com/anchore/syft/wiki/package-cataloger-selection#examples)
* [Using templates](https://github.com/anchore/syft/wiki/using-templates)
* [Multiple outputs](https://github.com/anchore/syft/wiki/multiple-outputs)
* [Private Registry Authentication](https://github.com/anchore/syft/wiki/private-registry-authentication)
  * [Local Docker Credentials](https://github.com/anchore/syft/wiki/private-registry-authentication#local-docker)
  * [Docker Credentials in Kubernetes](https://github.com/anchore/syft/wiki/private-registry-authentication#docker-credentials-in-kubernetes)
* [Attestation (experimental)](https://github.com/anchore/syft/wiki/attestation)
  * [Keyless Support](https://github.com/anchore/syft/wiki/attestation#keyless-support)
  * [Local private key support](https://github.com/anchore/syft/wiki/attestation#local-private-key-support)
  * [Adding an SBOM to an image as an attestation using Syft](https://github.com/anchore/syft/wiki/attestation#adding-an-sbom-to-an-image-as-an-attestation-using-syft)
* [Configuration](https://github.com/anchore/syft/wiki/configuration)

## Contributing

Check out our [contributing](/CONTRIBUTING.md) guide and [developer](/DEVELOPING.md) docs.

## Syft Team Meetings

The Syft Team hold regular community meetings online. All are welcome to join to bring topics for discussion. 
- Check the [calendar](https://calendar.google.com/calendar/u/0/r?cid=Y182OTM4dGt0MjRtajI0NnNzOThiaGtnM29qNEBncm91cC5jYWxlbmRhci5nb29nbGUuY29t) for the next meeting date. 
- Add items to the [agenda](https://docs.google.com/document/d/1ZtSAa6fj2a6KRWviTn3WoJm09edvrNUp4Iz_dOjjyY8/edit?usp=sharing) (join [this group](https://groups.google.com/g/anchore-oss-community) for write access to the [agenda](https://docs.google.com/document/d/1ZtSAa6fj2a6KRWviTn3WoJm09edvrNUp4Iz_dOjjyY8/edit?usp=sharing))
- See you there!

## Syft Logo

<p xmlns:cc="http://creativecommons.org/ns#" xmlns:dct="http://purl.org/dc/terms/"><a property="dct:title" rel="cc:attributionURL" href="https://anchore.com/wp-content/uploads/2024/11/syft-logo.svg">Syft Logo</a> by <a rel="cc:attributionURL dct:creator" property="cc:attributionName" href="https://anchore.com/">Anchore</a> is licensed under <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="license noopener noreferrer" style="display:inline-block;">CC BY 4.0<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/cc.svg" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/by.svg" alt=""></a></p>
