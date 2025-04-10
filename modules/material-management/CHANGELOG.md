# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [4.2.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.2.0...v4.2.1) (2025-04-10)

### Bug Fixes

- add serializationOptions flag for AAD UTF8 sorting ([#1581](https://github.com/aws/aws-encryption-sdk-javascript/issues/1581)) ([b80cad1](https://github.com/aws/aws-encryption-sdk-javascript/commit/b80cad14df361b4384aeed5753efb57c69d77377))

# [4.2.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.1.0...v4.2.0) (2025-02-27)

### Bug Fixes

- include uuid as a dependency in material-management ([#1564](https://github.com/aws/aws-encryption-sdk-javascript/issues/1564)) ([dee213b](https://github.com/aws/aws-encryption-sdk-javascript/commit/dee213bc91dd0cde8dd177da52b739e10129f514))

# [4.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.0.2...v4.1.0) (2025-01-16)

### Features

- Adding the hierarchical keyring ([#1537](https://github.com/aws/aws-encryption-sdk-javascript/issues/1537)) ([43dcb16](https://github.com/aws/aws-encryption-sdk-javascript/commit/43dcb166d5ac76d744ea283808006f65915b9730))

## [4.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.0.0...v4.0.1) (2024-07-30)

**Note:** Version bump only for package @aws-crypto/material-management

# [4.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.2.2...v4.0.0) (2023-07-17)

**Note:** Version bump only for package @aws-crypto/material-management

## [3.2.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.2.1...v3.2.2) (2023-07-05)

**Note:** Version bump only for package @aws-crypto/material-management

# [3.2.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.1.1...v3.2.0) (2023-02-23)

### Features

- Support AWS SDK v3 ([#1043](https://github.com/aws/aws-encryption-sdk-javascript/issues/1043)) ([33a9e43](https://github.com/aws/aws-encryption-sdk-javascript/commit/33a9e43b3808e67c0852a436ccfb3f0ffab844c2))

# [3.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.3...v3.1.0) (2021-11-10)

### Features

- **node:** support node v16 ([#741](https://github.com/aws/aws-encryption-sdk-javascript/issues/741)) ([66e63b5](https://github.com/aws/aws-encryption-sdk-javascript/commit/66e63b5af2dffa9ee128a323f14cbbb8520a5053))

# [3.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)

**Note:** Version bump only for package @aws-crypto/material-management

# [2.4.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package @aws-crypto/material-management

# [2.3.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)

### Features

- AWS KMS multi-Region Key support ([#631](https://github.com/aws/aws-encryption-sdk-javascript/issues/631)) ([701f811](https://github.com/aws/aws-encryption-sdk-javascript/commit/701f8113a63780f24b52340f63844e425ba0543b))

# [2.2.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/material-management@2.1.0...@aws-crypto/material-management@2.2.0) (2021-05-27)

**Note:** Version bump only for package @aws-crypto/material-management

# [2.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management@2.0.0...@aws-crypto/material-management@2.1.0) (2021-02-04)

**Note:** Version bump only for package @aws-crypto/material-management

# [2.0.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/material-management@1.7.0...@aws-crypto/material-management@2.0.0) (2020-09-25)

- feat!: Updates to the AWS Encryption SDK. ([0a8a581](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/0a8a581ab7c058735310016b819caaec6868c0a7))

### BREAKING CHANGES

- AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
  Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html

# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/material-management@1.0.4...@aws-crypto/material-management@1.7.0) (2020-09-24)

### Bug Fixes

- Update types for newer typescript versions ([#394](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/issues/394)) ([3069c63](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/3069c631e7b896e7b55b2b0aa1fa12a0a6413abf))

### Features

- Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))

## [1.0.4](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management@1.0.3...@aws-crypto/material-management@1.0.4) (2020-05-26)

### Bug Fixes

- add asserts to `needs` ([#327](https://github.com/aws/aws-encryption-sdk-javascript/issues/327)) ([c103fa4](https://github.com/aws/aws-encryption-sdk-javascript/commit/c103fa4cf58c89a1a9b57a70744a92e23d923c74))

## [1.0.3](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management@1.0.2...@aws-crypto/material-management@1.0.3) (2020-04-02)

### Bug Fixes

- Duplicate `’algorithm’` check ([1b876dc](https://github.com/aws/aws-encryption-sdk-javascript/commit/1b876dc53fc539306fd8264e166e8f5cee1a1c0b))
- for MSRCrypto 1.6.0 ([cf7e389](https://github.com/aws/aws-encryption-sdk-javascript/commit/cf7e3895aa57b78f89c1c7ec541724f7fe9e6616))
- Kdf keys should have an algorithm name of ‘HKDF’ ([6100d1d](https://github.com/aws/aws-encryption-sdk-javascript/commit/6100d1deeb60a6d4ef80efd12c258b5ebc0cef1d))

## [1.0.2](/compare/@aws-crypto/material-management@1.0.1...@aws-crypto/material-management@1.0.2) (2020-02-07)

### Bug Fixes

- lerna version maintains package-lock (#235) c901318, closes #235 #234

## [1.0.1](/compare/@aws-crypto/material-management@1.0.0...@aws-crypto/material-management@1.0.1) (2019-10-15)

### Bug Fixes

- eval in portableTimingSafeEqual (#227) edd41f2, closes #227

# [1.0.0](/compare/@aws-crypto/material-management@0.2.0-preview.4...@aws-crypto/material-management@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/material-management

# [0.2.0-preview.4](/compare/@aws-crypto/material-management@0.2.0-preview.3...@aws-crypto/material-management@0.2.0-preview.4) (2019-09-20)

### Bug Fixes

- Better error messageing (#212) 7198100, closes #212 #152
- Better timingSafeEqual definition (#203) 12d1661, closes #203
- KeyringTraceFlag requirements and data key caching (#210) 7dfa1ae, closes #210

### Features

- Remove unencryptedDataKeyLength (#201) bd160c0, closes #201
- Suport Node.js crypto KeyObjects (#200) 77ad031, closes #200 #74

### BREAKING CHANGES

- CryptographicMaterial no longer support `unencryptedDataKeyLength`

# [0.2.0-preview.3](/compare/@aws-crypto/material-management@0.2.0-preview.2...@aws-crypto/material-management@0.2.0-preview.3) (2019-08-08)

### Bug Fixes

- Conditions for materials-management (#185) 7f7228b, closes #185
- Encryption Context changes (#148) 5a7e9ca, closes #148 #54
- framLength is not passed to the CMM (#190) b60f653, closes #190 #161
- Multi keyrings should not require a generator (#165) 11ff819, closes #165

### BREAKING CHANGES

- CryptographicMaterial now require `encryptionContext` on creation.
  this includes `NodeDecryptionMaterial`, `NodeEncryptionMaterial`,
  `WebCryptoEncryptionMaterial`, and `WebCryptoDecryptionMaterial`.
- The Keyring base class no longer accepts `encryptionContext`
  for `onDecrypt` and `onEncrypt`.
  It now gets this value from the CryptographicMaterial passed.
- The CMM interface now returns CryptographicMaterial
  instead of a complex object with material and context.

# [0.2.0-preview.2](/compare/@aws-crypto/material-management@0.2.0-preview.1...@aws-crypto/material-management@0.2.0-preview.2) (2019-07-24)

### Bug Fixes

- 192 bit algorithm suite support in browsers (#131) 8a4d708, closes #131
- Always explicitly catch exceptions. (#132) bf88871, closes #132
- material-management should not export DOM types (#147) 0f4dd7e, closes #147 #137

# [0.2.0-preview.1](/compare/@aws-crypto/material-management@0.2.0-preview.0...@aws-crypto/material-management@0.2.0-preview.1) (2019-06-21)

### Bug Fixes

- package.json files path update (#120) fbc3270, closes #120

# 0.2.0-preview.0 (2019-06-21)

### Bug Fixes

- browser integration (#57) 1285e0e, closes #57
- Browser things for integration module (#56) a2c46c1, closes #56
- Default CMM should not be required (#80) 465de6c, closes #80 #44 #70
- dependencies and lint (#75) 5324491, closes #75
- EncryptedDataKey providerInfo (#36) 5da3b86, closes #36
- LICENSE file needs date and owner e0f7085
- MultiKeyring instanceof (#35) b21aca7, closes #35
- portableTimingSafeEqual may be optimized (#73) 688e81e, closes #73
- signatureCurve property on keys (#98) ba92ebd, closes #98
- Update nyc version fcfa3af

### Features

- cacheing material management (#38) 7dd6532, closes #38
- raw AES keyring helpers (#37) 1a5080f, closes #37
