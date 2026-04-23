# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [5.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.2.2...v5.0.0) (2026-04-23)

### Bug Fixes

- add repository fields and enable npm provenance for Sigstore OIDC publishing ([0105088](https://github.com/aws/aws-encryption-sdk-javascript/commit/010508876ff489c548261303a98b04bd7dc97e74))
- correct repository URLs from awslabs to aws org for npm provenance ([f5699bc](https://github.com/aws/aws-encryption-sdk-javascript/commit/f5699bce36c15a72545924b2bdfda6148a7933e1))
- Removes the internal added prefix from custom encryption context before creating the branch key material node object ([#1650](https://github.com/aws/aws-encryption-sdk-javascript/issues/1650)) ([9907b1b](https://github.com/aws/aws-encryption-sdk-javascript/commit/9907b1ba70233edf96ce56eb0e8eb094b93c517f))

### Features

- Adds create and version branch key functionality ([#1652](https://github.com/aws/aws-encryption-sdk-javascript/issues/1652)) ([6fab564](https://github.com/aws/aws-encryption-sdk-javascript/commit/6fab56475d4d2521bca859a66f7ce759aad7ba44)), closes [#1642](https://github.com/aws/aws-encryption-sdk-javascript/issues/1642)

### Reverts

- Revert "v5.0.0" ([4c6f731](https://github.com/aws/aws-encryption-sdk-javascript/commit/4c6f7319c297437357853cb7f8e3d5170369fe60))
- Revert "v5.0.0" ([e3d58fb](https://github.com/aws/aws-encryption-sdk-javascript/commit/e3d58fbadb8456c1acbcdabe8ac122aba4e8d455))
- Revert "v5.0.0" ([0ee917e](https://github.com/aws/aws-encryption-sdk-javascript/commit/0ee917e08b202c93d10927eb279132ae03634c0d))

## [4.2.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.2.1...v4.2.2) (2026-03-05)

### Bug Fixes

- **deps:** add missing dependency ([#1629](https://github.com/aws/aws-encryption-sdk-javascript/issues/1629)) ([7329fb7](https://github.com/aws/aws-encryption-sdk-javascript/commit/7329fb700cc09f116f4270d6343324d80d4d4820))

## [4.2.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.2.0...v4.2.1) (2025-04-10)

### Bug Fixes

- add serializationOptions flag for AAD UTF8 sorting ([#1581](https://github.com/aws/aws-encryption-sdk-javascript/issues/1581)) ([b80cad1](https://github.com/aws/aws-encryption-sdk-javascript/commit/b80cad14df361b4384aeed5753efb57c69d77377))

# [4.2.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.1.0...v4.2.0) (2025-02-27)

**Note:** Version bump only for package @aws-crypto/branch-keystore-node

# [4.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v4.0.2...v4.1.0) (2025-01-16)

### Features

- Adding the hierarchical keyring ([#1537](https://github.com/aws/aws-encryption-sdk-javascript/issues/1537)) ([43dcb16](https://github.com/aws/aws-encryption-sdk-javascript/commit/43dcb166d5ac76d744ea283808006f65915b9730))
