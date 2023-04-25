# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.3.1] - 2023-04-25

### Added

- Add the use of the runtime/default seccomp profile.
- Add icon.

## [2.3.0] - 2022-11-22

### Added

- Add login using kubernetes auth in the scraping function to catch storage-level errors.

### Removed

- Don't push releases to KVM app collection.

## [2.2.1] - 2022-06-16

### Added

- Push to `giantswarm-playground-catalog`.

### Changed

- Update `architect-orb` to v4.8.0 to stop pushing to app collection helm chart.

## [2.2.0] - 2021-07-27

### Added

- Add `giantswarm.io/monitoring: "true"` label to enable Prometheus autodiscovery.

## [2.1.0] 2021-05-26

## [2.0.0] 2020-05-27

### Changed

- Update labels and selector labels.
- Change docker image templating.
- Change user/group ID templating.

### Removed

- Remove name and namespace from values.yaml.

## [1.0.0] 2019-08-13

## [0.1.0]  2019-08-13

[Unreleased]: https://github.com/giantswarm/vault-exporter/compare/v2.3.1...HEAD
[2.3.1]: https://github.com/giantswarm/vault-exporter/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/giantswarm/vault-exporter/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/giantswarm/vault-exporter/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/giantswarm/vault-exporter/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/giantswarm/vault-exporter/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/giantswarm/vault-exporter/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/giantswarm/vault-exporter/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/giantswarm/vault-exporter/releases/tag/v0.1.0
