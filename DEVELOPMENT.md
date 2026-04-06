# Syft alauda Branch Development Guide

## Background

Previously, syft was used as a general-purpose CLI across multiple plugins, each needing to fix vulnerabilities in syft itself.

To avoid duplicate work, we forked the current repository from [syft](https://github.com/anchore/syft.git) and maintain it through the `alauda-vx.xx.xx` branch.

We use [renovate](https://gitlab-ce.alauda.cn/devops/tech-research/renovate/-/blob/main/docs/quick-start/0002-quick-start.md) to automatically fix vulnerabilities in corresponding versions.

## Repository Structure

Based on the original code, the following content has been added:

- [alauda-auto-tag.yaml](./.github/workflows/alauda-auto-tag.yaml): Automatically tags and triggers goreleaser when a PR is merged into the `alauda-vx.xx.xx` branch.
- [release-alauda.yaml](./.github/workflows/release-alauda.yaml): Supports triggering goreleaser via tag updates or manual triggers (this pipeline is not triggered when tags are automatically created within actions, as actions are designed not to recursively trigger multiple actions).
- [reusable-release-alauda.yaml](./.github/workflows/reusable-release-alauda.yaml): Executes goreleaser to create a release.
- [scan-alauda.yaml](.github/workflows/scan-alauda.yaml): Runs trivy vulnerability scans (`rootfs` scans Go binaries).
- [.goreleaser-alauda.yml](.goreleaser-alauda.yml): Configuration file for releasing alauda versions.

## Special Modifications

1. The official [test pipeline](.github/workflows/validations.yaml) originally used a paid runner. It has been adjusted to use free runners, and Unit Tests have been temporarily skipped (relying on Integration Tests as the safety net).

## Pipelines

### Triggered When Pull Request is Submitted

- [validations.yaml](.github/workflows/validations.yaml): Official test pipeline, including integration tests, etc.

### Triggered When Merged into alauda-vx.xx.xx Branch

- [alauda-auto-tag.yaml](./.github/workflows/alauda-auto-tag.yaml): Automatically tags and triggers goreleaser.
- [reusable-release-alauda.yaml](./.github/workflows/reusable-release-alauda.yaml): Executes goreleaser to create a release (triggered by `alauda-auto-tag.yaml`).

### Triggered by Schedule or Manual Operation

- [scan-alauda.yaml](.github/workflows/scan-alauda.yaml): Runs trivy vulnerability scans (`rootfs` scans Go binaries).

### Others

Other officially maintained pipelines remain unchanged. Some irrelevant pipelines have been disabled on the Actions page.

## Renovate Vulnerability Fixing Mechanism

The renovate configuration file is [renovate.json](https://github.com/AlaudaDevops/trivy/blob/main/renovate.json)

1. renovate detects vulnerabilities in the branch and submits a PR for fixes.
2. The PR automatically runs tests.
3. After all tests pass, renovate automatically merges the PR.
4. When the branch updates, an action automatically creates a tag (e.g., v1.42.4-alauda-0, both patch version and the last digit increment).
5. goreleaser automatically publishes a release based on the tag.

## Maintenance Plan

When upgrading to a new version, follow these steps:

1. Create an alauda branch from the corresponding tag, e.g., tag `v1.42.3` corresponds to branch `alauda-v1.42.3`.
2. Cherry-pick previous alauda branch changes to the new branch and push.

Renovate automatic fixing mechanism:
1. After renovate submits a PR, the pipeline will run automatically. If all tests pass, the PR will be automatically merged.
2. After merging into the `alauda-v1.42.3` branch, goreleaser will automatically create a `v1.42.4-alauda-0` release (note: not `v1.42.3-alauda-0`, because upgrading the version allows renovate to recognize it).
3. renovate configured in other plugins will automatically fetch artifacts from the release according to its configuration.
