# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [3.0.3](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.2...v3.0.3) (2021-09-21)

**Note:** Version bump only for package @aws-crypto/integration-node





## [3.0.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.2) (2021-09-08)

**Note:** Version bump only for package @aws-crypto/integration-node





## [3.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.1) (2021-09-07)

**Note:** Version bump only for package @aws-crypto/integration-node





# [3.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)


### chore

* update dependencies ([417db72](https://github.com/aws/aws-encryption-sdk-javascript/commit/417db726ecbc974a744e8e59ed07c4f94c46464a))


### BREAKING CHANGES

* This commit upgrades dependencies to no longer support Node 8 and 10.





# [2.4.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package @aws-crypto/integration-node





## [2.3.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.0...v2.3.1) (2021-07-01)

**Note:** Version bump only for package @aws-crypto/integration-node





# [2.3.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)


### Features

* AWS KMS multi-Region Key support ([#631](https://github.com/aws/aws-encryption-sdk-javascript/issues/631)) ([701f811](https://github.com/aws/aws-encryption-sdk-javascript/commit/701f8113a63780f24b52340f63844e425ba0543b))





## [2.2.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.0...v2.2.1) (2021-06-04)

**Note:** Version bump only for package @aws-crypto/integration-node





# [2.2.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/integration-node@2.1.0...@aws-crypto/integration-node@2.2.0) (2021-05-27)

**Note:** Version bump only for package @aws-crypto/integration-node






# [2.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/integration-node@2.0.0...@aws-crypto/integration-node@2.1.0) (2021-02-04)

**Note:** Version bump only for package @aws-crypto/integration-node





# [2.0.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/integration-node@1.7.0...@aws-crypto/integration-node@2.0.0) (2020-09-25)

**Note:** Version bump only for package @aws-crypto/integration-node





# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/integration-node@1.2.1...@aws-crypto/integration-node@1.7.0) (2020-09-24)


### Features

* Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))





## [1.2.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/integration-node@1.2.0...@aws-crypto/integration-node@1.2.1) (2020-05-26)

**Note:** Version bump only for package @aws-crypto/integration-node





# [1.2.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/integration-node@1.1.0...@aws-crypto/integration-node@1.2.0) (2020-04-02)


### Features

* Add concurrency for running tests ([#243](https://github.com/aws/aws-encryption-sdk-javascript/issues/243)) ([b9cd571](https://github.com/aws/aws-encryption-sdk-javascript/commit/b9cd5712ea90822c49c5fb81fbeb2bee06e33f21))
* Move to yauzl to fix FD error ([#264](https://github.com/aws/aws-encryption-sdk-javascript/issues/264)) ([1dd5a86](https://github.com/aws/aws-encryption-sdk-javascript/commit/1dd5a864fb7acf212a5aa397b42aa2bdee6567fc))
* Update the concurrency option to support cpu ([44475b5](https://github.com/aws/aws-encryption-sdk-javascript/commit/44475b51a86b9c148523254bec12a44981037aa0))





# [1.1.0](/compare/@aws-crypto/integration-node@1.0.2...@aws-crypto/integration-node@1.1.0) (2020-02-07)


### Bug Fixes

* lerna version maintains package-lock (#235) c901318, closes #235 #234


### Features

* Support sha256, sha384, and sha512 for OAEP padding (#240) 81b4562, closes #240 #198 nodejs/node#28335





## [1.0.2](/compare/@aws-crypto/integration-node@1.0.1...@aws-crypto/integration-node@1.0.2) (2019-11-12)

**Note:** Version bump only for package @aws-crypto/integration-node





## [1.0.1](/compare/@aws-crypto/integration-node@1.0.0...@aws-crypto/integration-node@1.0.1) (2019-10-15)

**Note:** Version bump only for package @aws-crypto/integration-node





# [1.0.0](/compare/@aws-crypto/integration-node@0.2.0-preview.5...@aws-crypto/integration-node@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/integration-node





# [0.2.0-preview.5](/compare/@aws-crypto/integration-node@0.2.0-preview.4...@aws-crypto/integration-node@0.2.0-preview.5) (2019-09-20)


### Bug Fixes

* Encrypt name to result (#211) 03061d1, closes #211
* integration silent errors (#197) fc91a71, closes #197





# [0.2.0-preview.4](/compare/@aws-crypto/integration-node@0.2.0-preview.3...@aws-crypto/integration-node@0.2.0-preview.4) (2019-08-08)

**Note:** Version bump only for package @aws-crypto/integration-node





# [0.2.0-preview.3](/compare/@aws-crypto/integration-node@0.2.0-preview.2...@aws-crypto/integration-node@0.2.0-preview.3) (2019-07-24)


### Features

* Encryption tests for integration-node (#153) d7b5e73, closes #153

### BREAKING CHANGES

* The cli now takes `encrypt` and `decrypt` as a command,
instead of only supporting decrypt testing.




# [0.2.0-preview.2](/compare/@aws-crypto/integration-node@0.2.0-preview.1...@aws-crypto/integration-node@0.2.0-preview.2) (2019-06-22)

**Note:** Version bump only for package @aws-crypto/integration-node





# [0.2.0-preview.1](/compare/@aws-crypto/integration-node@0.2.0-preview.0...@aws-crypto/integration-node@0.2.0-preview.1) (2019-06-21)


### Bug Fixes

* package.json files path update (#120) fbc3270, closes #120





# 0.2.0-preview.0 (2019-06-21)


### Bug Fixes

* Default CMM should not be required (#80) 465de6c, closes #80 #44 #70
* dependencies and lint (#75) 5324491, closes #75
* LICENSE file needs date and owner e0f7085
* Update integration-node readme  (#96) 6050b9a, closes #96


### Features

* add client libraries (#89) 24c72da, closes #89
* Add integration testing to CI (#115) 15da0ce, closes #115
* integration-node (#67) e6f3d91, closes #67
