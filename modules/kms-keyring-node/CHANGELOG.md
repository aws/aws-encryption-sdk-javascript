# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

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
