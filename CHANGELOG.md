# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [4.2.1](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v4.2.0...v4.2.1) (2025-04-10)

### Bug Fixes

- add serializationOptions flag for AAD UTF8 sorting ([#1581](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1581)) ([b80cad1](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/b80cad14df361b4384aeed5753efb57c69d77377))

# [4.2.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v4.1.0...v4.2.0) (2025-02-27)

### Bug Fixes

- include uuid as a dependency in material-management ([#1564](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1564)) ([dee213b](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/dee213bc91dd0cde8dd177da52b739e10129f514))

### Features

- integration-node can produce decrypt manifests ([#1580](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1580)) ([95f0fa1](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/95f0fa10b7d94ccc142fc2e89b2ffa49620285c9))

# [4.1.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v4.0.2...v4.1.0) (2025-01-16)

### Features

- Adding the hierarchical keyring ([#1537](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1537)) ([43dcb16](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/43dcb166d5ac76d744ea283808006f65915b9730))

## [4.0.2](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v4.0.1...v4.0.2) (2024-10-21)

**Note:** Version bump only for package aws-encryption-sdk-javascript

## [4.0.1](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v4.0.0...v4.0.1) (2024-07-30)

### Bug Fixes

- Add CVE-2023-46809 option to integration node ([#1424](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1424)) ([84a7034](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/84a703440aa7313ad0c779e50b7c052aa8dd5e7b))
- **CI:** npx_verdaccio ([#1190](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1190)) ([1051f19](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/1051f19578ba54bc476a30dedf5779576cf46d9f))

# [4.0.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.2.2...v4.0.0) (2023-07-17)

- feat!: Remove AWS SDK V2 Dependency (#1180) ([1d74248](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/1d742489b436748a656ecc2abce00e99353d1d62)), closes [#1180](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1180)

### BREAKING CHANGES

- The AWS Encryption SDK for JavaScript:

* requires the AWS SDK for JavaScript V3's kms-client (if using the KMS Keyring).
* no longer requires the AWS SDK V2
* no longer tests against nor supports NodeJS 12 or 14

## [3.2.2](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.2.1...v3.2.2) (2023-07-05)

### Bug Fixes

- **CD:** CodeBuild MUST USE a supported Node Version ([#1183](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1183)) ([e97b9c9](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/e97b9c915d9cb32b6fd8bcd5aae2397e812be344))

## [3.2.1](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.2.0...v3.2.1) (2023-07-05)

**Note:** Version bump only for package aws-encryption-sdk-javascript

# [3.2.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.1.1...v3.2.0) (2023-02-23)

### Features

- Support AWS SDK v3 ([#1043](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1043)) ([33a9e43](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/33a9e43b3808e67c0852a436ccfb3f0ffab844c2))
- Support Node v18 ([#1041](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1041)) ([5f39e1e](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/5f39e1ec61527473a0b9673f82259a75c2e37370))

## [3.1.1](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.1.0...v3.1.1) (2022-03-15)

### Bug Fixes

- browser-encrypt can encrypt 0 bytes ([#866](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/866)) ([32f7fa2](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/32f7fa245b5f9fc69a3c64309ccda5ae42a842b2))

# [3.1.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.0.3...v3.1.0) (2021-11-10)

### Bug Fixes

- Pin karma-credential-loader to 3.38.0 ([#795](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/795)) ([fe63723](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/fe63723d1b6cc6ce68832ba5cc87c9c980f1f39e))

### Features

- **node:** support node v16 ([#741](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/741)) ([66e63b5](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/66e63b5af2dffa9ee128a323f14cbbb8520a5053))

## [3.0.3](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.0.2...v3.0.3) (2021-09-21)

### Bug Fixes

- Revert [#7](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/7)ba9425166ce0adc5feda67415e514f4d5616b87 ([#748](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/748)) ([9e7150a](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/9e7150a42f1f1afaca03e36817697bd1781daedd)), closes [#7ba9425166ce0adc5feda67415e514f4d5616b87](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/7ba9425166ce0adc5feda67415e514f4d5616b87)

## [3.0.2](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.2) (2021-09-08)

### Bug Fixes

- Update @types/node to 16.7.9 ([#723](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/723)) ([7ba9425](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/7ba9425166ce0adc5feda67415e514f4d5616b87))

## [3.0.1](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.1) (2021-09-07)

### Bug Fixes

- Update @types/node to 16.7.9 ([#723](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/723)) ([7ba9425](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/7ba9425166ce0adc5feda67415e514f4d5616b87))

# [3.0.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)

### chore

- remove node 10 from CI ([64cc85b](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/64cc85b00d231d058b4237045e2b5f5b917d582e))
- update dependencies ([417db72](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/417db726ecbc974a744e8e59ed07c4f94c46464a))

### BREAKING CHANGES

- Removing CI coverage for Node 10
- This commit upgrades dependencies to no longer support Node 8 and 10.

# [2.4.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package aws-encryption-sdk-javascript

## [2.3.1](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v2.3.0...v2.3.1) (2021-07-01)

### Bug Fixes

- der2raw sLength is s byte length ([#634](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/634)) ([46cd178](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/46cd1789744064679a294f49c21ec05f95057b82))

# [2.3.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)

### Features

- AWS KMS multi-Region Key support ([#631](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/631)) ([701f811](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/701f8113a63780f24b52340f63844e425ba0543b))

## [2.2.1](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v2.2.0...v2.2.1) (2021-06-04)

### Bug Fixes

- Track version from package.json ([#616](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/616)) ([4be2ed4](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/4be2ed4a71106dc79379ac76fedc12234d8f6834))
