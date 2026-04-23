# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [5.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.2.2...v5.0.0) (2026-04-23)

### Bug Fixes

- add repository fields and enable npm provenance for Sigstore OIDC publishing ([0105088](https://github.com/aws/aws-encryption-sdk-javascript/commit/010508876ff489c548261303a98b04bd7dc97e74))
- correct repository URLs from awslabs to aws org for npm provenance ([f5699bc](https://github.com/aws/aws-encryption-sdk-javascript/commit/f5699bce36c15a72545924b2bdfda6148a7933e1))
- mitigate dependency issues — remove deprecated packages ([#1654](https://github.com/aws/aws-encryption-sdk-javascript/issues/1654)) ([d795278](https://github.com/aws/aws-encryption-sdk-javascript/commit/d795278bfc6f9d023545f0b36bef701ba5387081))

### Reverts

- Revert "v5.0.0" ([4c6f731](https://github.com/aws/aws-encryption-sdk-javascript/commit/4c6f7319c297437357853cb7f8e3d5170369fe60))
- Revert "v5.0.0" ([e3d58fb](https://github.com/aws/aws-encryption-sdk-javascript/commit/e3d58fbadb8456c1acbcdabe8ac122aba4e8d455))
- Revert "v5.0.0" ([0ee917e](https://github.com/aws/aws-encryption-sdk-javascript/commit/0ee917e08b202c93d10927eb279132ae03634c0d))

## [4.2.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.2.1...v4.2.2) (2026-03-05)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

## [4.2.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.2.0...v4.2.1) (2025-04-10)

### Bug Fixes

- add serializationOptions flag for AAD UTF8 sorting ([#1581](https://github.com/aws/aws-encryption-sdk-javascript/issues/1581)) ([b80cad1](https://github.com/aws/aws-encryption-sdk-javascript/commit/b80cad14df361b4384aeed5753efb57c69d77377))

# [4.2.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.1.0...v4.2.0) (2025-02-27)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [4.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.0.2...v4.1.0) (2025-01-16)

### Features

- Adding the hierarchical keyring ([#1537](https://github.com/aws/aws-encryption-sdk-javascript/issues/1537)) ([43dcb16](https://github.com/aws/aws-encryption-sdk-javascript/commit/43dcb166d5ac76d744ea283808006f65915b9730))

## [4.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.0.0...v4.0.1) (2024-07-30)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [4.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.2.2...v4.0.0) (2023-07-17)

- feat!: Remove AWS SDK V2 Dependency (#1180) ([1d74248](https://github.com/aws/aws-encryption-sdk-javascript/commit/1d742489b436748a656ecc2abce00e99353d1d62)), closes [#1180](https://github.com/aws/aws-encryption-sdk-javascript/issues/1180)

### BREAKING CHANGES

- The AWS Encryption SDK for JavaScript:

* requires the AWS SDK for JavaScript V3's kms-client (if using the KMS Keyring).
* no longer requires the AWS SDK V2
* no longer tests against nor supports NodeJS 12 or 14

## [3.2.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.2.1...v3.2.2) (2023-07-05)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [3.2.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.1.1...v3.2.0) (2023-02-23)

### Features

- Support AWS SDK v3 ([#1043](https://github.com/aws/aws-encryption-sdk-javascript/issues/1043)) ([33a9e43](https://github.com/aws/aws-encryption-sdk-javascript/commit/33a9e43b3808e67c0852a436ccfb3f0ffab844c2))

# [3.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.3...v3.1.0) (2021-11-10)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

## [3.0.3](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.2...v3.0.3) (2021-09-21)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

## [3.0.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.2) (2021-09-08)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

## [3.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.1) (2021-09-07)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [3.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [2.4.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

## [2.3.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.0...v2.3.1) (2021-07-01)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [2.3.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)

### Features

- AWS KMS multi-Region Key support ([#631](https://github.com/aws/aws-encryption-sdk-javascript/issues/631)) ([701f811](https://github.com/aws/aws-encryption-sdk-javascript/commit/701f8113a63780f24b52340f63844e425ba0543b))

## [2.2.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.0...v2.2.1) (2021-06-04)

### Bug Fixes

- Track version from package.json ([#616](https://github.com/aws/aws-encryption-sdk-javascript/issues/616)) ([4be2ed4](https://github.com/aws/aws-encryption-sdk-javascript/commit/4be2ed4a71106dc79379ac76fedc12234d8f6834))

# [2.2.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/kms-keyring-node@2.1.0...@aws-crypto/kms-keyring-node@2.2.0) (2021-05-27)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [2.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/kms-keyring-node@2.0.0...@aws-crypto/kms-keyring-node@2.1.0) (2021-02-04)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [2.0.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/kms-keyring-node@1.7.0...@aws-crypto/kms-keyring-node@2.0.0) (2020-09-25)

- feat!: Updates to the AWS Encryption SDK. ([0a8a581](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/0a8a581ab7c058735310016b819caaec6868c0a7))

### BREAKING CHANGES

- AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
  Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html

# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/kms-keyring-node@1.0.5...@aws-crypto/kms-keyring-node@1.7.0) (2020-09-24)

### Features

- Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))

## [1.0.5](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/kms-keyring-node@1.0.4...@aws-crypto/kms-keyring-node@1.0.5) (2020-05-26)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

## [1.0.4](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/kms-keyring-node@1.0.3...@aws-crypto/kms-keyring-node@1.0.4) (2020-04-02)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

## [1.0.3](/compare/@aws-crypto/kms-keyring-node@1.0.2...@aws-crypto/kms-keyring-node@1.0.3) (2020-02-07)

### Bug Fixes

- lerna version maintains package-lock (#235) c901318, closes #235 #234

## [1.0.2](/compare/@aws-crypto/kms-keyring-node@1.0.1...@aws-crypto/kms-keyring-node@1.0.2) (2019-11-12)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

## [1.0.1](/compare/@aws-crypto/kms-keyring-node@1.0.0...@aws-crypto/kms-keyring-node@1.0.1) (2019-10-15)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [1.0.0](/compare/@aws-crypto/kms-keyring-node@0.1.0-preview.4...@aws-crypto/kms-keyring-node@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/kms-keyring-node

# [0.1.0-preview.4](/compare/@aws-crypto/kms-keyring-node@0.1.0-preview.3...@aws-crypto/kms-keyring-node@0.1.0-preview.4) (2019-09-20)

### Bug Fixes

- Update user agent calls to KMS (#205) a5dd6c2, closes #205

### Features

- Suport Node.js crypto KeyObjects (#200) 77ad031, closes #200 #74

# [0.1.0-preview.3](/compare/@aws-crypto/kms-keyring-node@0.1.0-preview.2...@aws-crypto/kms-keyring-node@0.1.0-preview.3) (2019-08-08)

### Bug Fixes

- Encryption Context changes (#148) 5a7e9ca, closes #148 #54

# [0.1.0-preview.2](/compare/@aws-crypto/kms-keyring-node@0.1.0-preview.1...@aws-crypto/kms-keyring-node@0.1.0-preview.2) (2019-07-24)

### Bug Fixes

- aws sdk version dependencies pollution (#145) d73d50d, closes #145 #136 #138

# [0.1.0-preview.1](/compare/@aws-crypto/kms-keyring-node@0.1.0-preview.0...@aws-crypto/kms-keyring-node@0.1.0-preview.1) (2019-06-21)

### Bug Fixes

- package.json files path update (#120) fbc3270, closes #120

# 0.1.0-preview.0 (2019-06-21)

### Bug Fixes

- dependencies and lint (#75) 5324491, closes #75
- LICENSE file needs date and owner e0f7085
- Update nyc version fcfa3af

### Features

- kms-keyring-node initial commit (#11) e2dd7ad, closes #11
- kms-keyring-node tests (#108) 8c79529, closes #108
- support v2 and v3 AWS SDK-JS (#66) 0706c31, closes #66
