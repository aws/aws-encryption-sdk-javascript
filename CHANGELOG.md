# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [5.0.0](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v4.2.2...v5.0.0) (2026-04-23)

### Bug Fixes

- **ci:** fix VERSION_BUMP scoping and remove unused NPM token from publish job ([#1653](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1653)) ([6fd56ea](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/6fd56ea4ac135bf7b28faa935b5cd20412ffd4bc))
- **ci:** force pull in publish step ([#1639](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1639)) ([6b74c8c](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/6b74c8cd573290f33ea0142ea3e5da68005e0468))
- **ci:** npm otp fix for publish ([#1641](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1641)) ([fcaf49f](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/fcaf49f31821f8453f8ad34e9766efd39084c5ca))
- **ci:** npm token for publish ([#1640](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1640)) ([953ae60](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/953ae609cd19e4bf508613bb06bac8ed3574f784))
- mitigate dependency issues — remove deprecated packages ([#1654](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1654)) ([d795278](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/d795278bfc6f9d023545f0b36bef701ba5387081))
- Removes the internal added prefix from custom encryption context before creating the branch key material node object ([#1650](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1650)) ([9907b1b](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/9907b1ba70233edf96ce56eb0e8eb094b93c517f))

- feat!: Drop IE11 support (#1651) ([f11b277](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/f11b277b802180e89532ff83bced7440e42247e0)), closes [#1651](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1651)

### Features

- Adds create and version branch key functionality ([#1652](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1652)) ([6fab564](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/6fab56475d4d2521bca859a66f7ce759aad7ba44)), closes [#1642](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1642)

### Reverts

- Revert "v5.0.0" ([0ee917e](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/0ee917e08b202c93d10927eb279132ae03634c0d))

### BREAKING CHANGES

- The AWS Encryption SDK for JavaScript no longer supports Internet Explorer 11 (IE11). The msCrypto shim and related IE11 detection code have been removed from the web-crypto-backend module.

Co-authored-by: Lucas McDonald <lucmcdon@amazon.com>

## [4.2.2](https://github.com/awslabs/aws-encryption-sdk-javascript/compare/v4.2.1...v4.2.2) (2026-03-05)

### Bug Fixes

- **ci-auth:** git release auth ([#1638](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1638)) ([04db819](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/04db819fca842432b714a45a92563045b241c14b))
- **ci-debug:** log auth username ([#1637](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1637)) ([27003a7](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/27003a78383947c105b3160f329f6af5fc89f826))
- **ci:** git auth ([#1636](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1636)) ([83d825d](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/83d825dcd15daf1736b27c4c906756ba8c685d52))
- **ci:** release bot credentials ([#1635](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1635)) ([4870b2c](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/4870b2c4b9f0e51da39693c56b9065e62c7c06c8))
- **deps:** add missing dependency ([#1629](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1629)) ([7329fb7](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/7329fb700cc09f116f4270d6343324d80d4d4820))
- remove usage of Buffer from top-level ([#1621](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1621)) ([9556272](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/955627223af2bbbb96a2ee69f2fe64504593aaf2))
- upgrade bn.js to 4.12.3/5.2.3 ([#1631](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1631)) ([ebbd60f](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/ebbd60f2af27a14f41a7a2bfcca6095dc953df0c))

- feat!: Remove support for NodeJs v16 ([ef26b39](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/ef26b39eb8c8078fcbae3482eaf5ce1ec37e61ba))

### Reverts

- Revert "feat!: Drop IE11 (#1625)" ([7d6902e](https://github.com/awslabs/aws-encryption-sdk-javascript/commit/7d6902e9f80e09434b2b901cf3317e056d872167)), closes [#1625](https://github.com/awslabs/aws-encryption-sdk-javascript/issues/1625)

### BREAKING CHANGES

- - no longer tests against nor supports NodeJS 16

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
