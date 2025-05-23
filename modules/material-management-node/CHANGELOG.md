# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [4.2.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.2.0...v4.2.1) (2025-04-10)

### Bug Fixes

- add serializationOptions flag for AAD UTF8 sorting ([#1581](https://github.com/aws/aws-encryption-sdk-javascript/issues/1581)) ([b80cad1](https://github.com/aws/aws-encryption-sdk-javascript/commit/b80cad14df361b4384aeed5753efb57c69d77377))

# [4.2.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.1.0...v4.2.0) (2025-02-27)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [4.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.0.2...v4.1.0) (2025-01-16)

**Note:** Version bump only for package @aws-crypto/material-management-node

## [4.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.0.0...v4.0.1) (2024-07-30)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [4.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.2.2...v4.0.0) (2023-07-17)

**Note:** Version bump only for package @aws-crypto/material-management-node

## [3.2.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.2.1...v3.2.2) (2023-07-05)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [3.2.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.1.1...v3.2.0) (2023-02-23)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [3.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.3...v3.1.0) (2021-11-10)

### Features

- **node:** support node v16 ([#741](https://github.com/aws/aws-encryption-sdk-javascript/issues/741)) ([66e63b5](https://github.com/aws/aws-encryption-sdk-javascript/commit/66e63b5af2dffa9ee128a323f14cbbb8520a5053))

## [3.0.3](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.2...v3.0.3) (2021-09-21)

### Bug Fixes

- Revert [#7](https://github.com/aws/aws-encryption-sdk-javascript/issues/7)ba9425166ce0adc5feda67415e514f4d5616b87 ([#748](https://github.com/aws/aws-encryption-sdk-javascript/issues/748)) ([9e7150a](https://github.com/aws/aws-encryption-sdk-javascript/commit/9e7150a42f1f1afaca03e36817697bd1781daedd)), closes [#7ba9425166ce0adc5feda67415e514f4d5616b87](https://github.com/aws/aws-encryption-sdk-javascript/issues/7ba9425166ce0adc5feda67415e514f4d5616b87)

## [3.0.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.2) (2021-09-08)

### Bug Fixes

- Update @types/node to 16.7.9 ([#723](https://github.com/aws/aws-encryption-sdk-javascript/issues/723)) ([7ba9425](https://github.com/aws/aws-encryption-sdk-javascript/commit/7ba9425166ce0adc5feda67415e514f4d5616b87))

## [3.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.1) (2021-09-07)

### Bug Fixes

- Update @types/node to 16.7.9 ([#723](https://github.com/aws/aws-encryption-sdk-javascript/issues/723)) ([7ba9425](https://github.com/aws/aws-encryption-sdk-javascript/commit/7ba9425166ce0adc5feda67415e514f4d5616b87))

# [3.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [2.4.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package @aws-crypto/material-management-node

## [2.3.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.0...v2.3.1) (2021-07-01)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [2.3.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)

### Features

- AWS KMS multi-Region Key support ([#631](https://github.com/aws/aws-encryption-sdk-javascript/issues/631)) ([701f811](https://github.com/aws/aws-encryption-sdk-javascript/commit/701f8113a63780f24b52340f63844e425ba0543b))

# [2.2.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/material-management-node@2.1.0...@aws-crypto/material-management-node@2.2.0) (2021-05-27)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [2.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management-node@2.0.0...@aws-crypto/material-management-node@2.1.0) (2021-02-04)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [2.0.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/material-management-node@1.7.0...@aws-crypto/material-management-node@2.0.0) (2020-09-25)

- feat!: Updates to the AWS Encryption SDK. ([0a8a581](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/0a8a581ab7c058735310016b819caaec6868c0a7))

### BREAKING CHANGES

- AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
  Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html

# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/material-management-node@1.0.5...@aws-crypto/material-management-node@1.7.0) (2020-09-24)

### Features

- Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))

## [1.0.5](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management-node@1.0.4...@aws-crypto/material-management-node@1.0.5) (2020-05-26)

**Note:** Version bump only for package @aws-crypto/material-management-node

## [1.0.4](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management-node@1.0.3...@aws-crypto/material-management-node@1.0.4) (2020-04-02)

**Note:** Version bump only for package @aws-crypto/material-management-node

## [1.0.3](/compare/@aws-crypto/material-management-node@1.0.2...@aws-crypto/material-management-node@1.0.3) (2020-02-07)

### Bug Fixes

- lerna version maintains package-lock (#235) c901318, closes #235 #234

## [1.0.2](/compare/@aws-crypto/material-management-node@1.0.1...@aws-crypto/material-management-node@1.0.2) (2019-11-12)

### Bug Fixes

- Import declaration conflicts with local declaration (#233) 4818074, closes #233 #232 #148

## [1.0.1](/compare/@aws-crypto/material-management-node@1.0.0...@aws-crypto/material-management-node@1.0.1) (2019-10-15)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [1.0.0](/compare/@aws-crypto/material-management-node@0.1.0-preview.4...@aws-crypto/material-management-node@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/material-management-node

# [0.1.0-preview.4](/compare/@aws-crypto/material-management-node@0.1.0-preview.3...@aws-crypto/material-management-node@0.1.0-preview.4) (2019-09-20)

### Bug Fixes

- ENCODED_SIGNER_KEY in encryption context e8b8efd

### Features

- Suport Node.js crypto KeyObjects (#200) 77ad031, closes #200 #74

# [0.1.0-preview.3](/compare/@aws-crypto/material-management-node@0.1.0-preview.2...@aws-crypto/material-management-node@0.1.0-preview.3) (2019-08-08)

### Bug Fixes

- Encryption Context changes (#148) 5a7e9ca, closes #148 #54

# [0.1.0-preview.2](/compare/@aws-crypto/material-management-node@0.1.0-preview.1...@aws-crypto/material-management-node@0.1.0-preview.2) (2019-07-24)

### Features

- Node.js Typescript version dependency (#146) 9dfa857, closes #146 #135 #74

# [0.1.0-preview.1](/compare/@aws-crypto/material-management-node@0.1.0-preview.0...@aws-crypto/material-management-node@0.1.0-preview.1) (2019-06-21)

### Bug Fixes

- package.json files path update (#120) fbc3270, closes #120

# 0.1.0-preview.0 (2019-06-21)

### Bug Fixes

- Default CMM should not be required (#80) 465de6c, closes #80 #44 #70
- dependencies and lint (#75) 5324491, closes #75
- KDF behavior (#77) c51d46d, closes #77 #59
- LICENSE file needs date and owner e0f7085
- Update nyc version fcfa3af

### Features

- cacheing material management (#38) 7dd6532, closes #38
- material-management-node initial commit (#8) b61fe3c, closes #8
- support v2 and v3 AWS SDK-JS (#66) 0706c31, closes #66
