# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [3.0.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.2) (2021-09-08)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





## [3.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.1) (2021-09-07)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [3.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [2.4.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





## [2.3.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.0...v2.3.1) (2021-07-01)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [2.3.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [2.2.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/decrypt-browser@2.1.0...@aws-crypto/decrypt-browser@2.2.0) (2021-05-27)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [2.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/decrypt-browser@2.0.0...@aws-crypto/decrypt-browser@2.1.0) (2021-02-04)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [2.0.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/decrypt-browser@1.7.0...@aws-crypto/decrypt-browser@2.0.0) (2020-09-25)


* feat!: Updates to the AWS Encryption SDK. ([0a8a581](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/0a8a581ab7c058735310016b819caaec6868c0a7))


### BREAKING CHANGES

* AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html





# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/decrypt-browser@1.1.2...@aws-crypto/decrypt-browser@1.7.0) (2020-09-24)


### Features

* Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))





## [1.1.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/decrypt-browser@1.1.1...@aws-crypto/decrypt-browser@1.1.2) (2020-05-26)


### Bug Fixes

* resource exhaustion from an incomplete encrypted message ([#348](https://github.com/aws/aws-encryption-sdk-javascript/issues/348)) ([8c81013](https://github.com/aws/aws-encryption-sdk-javascript/commit/8c810131986b782c0702da4988b3999279daf2a3))





## [1.1.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/decrypt-browser@1.1.0...@aws-crypto/decrypt-browser@1.1.1) (2020-04-02)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [1.1.0](/compare/@aws-crypto/decrypt-browser@1.0.3...@aws-crypto/decrypt-browser@1.1.0) (2020-02-07)


### Features

* Update version of dependencies (#241) cf404a4, closes #241





## [1.0.3](/compare/@aws-crypto/decrypt-browser@1.0.2...@aws-crypto/decrypt-browser@1.0.3) (2020-02-07)


### Bug Fixes

* lerna version maintains package-lock (#235) c901318, closes #235 #234





## [1.0.2](/compare/@aws-crypto/decrypt-browser@1.0.1...@aws-crypto/decrypt-browser@1.0.2) (2019-11-12)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





## [1.0.1](/compare/@aws-crypto/decrypt-browser@1.0.0...@aws-crypto/decrypt-browser@1.0.1) (2019-10-15)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [1.0.0](/compare/@aws-crypto/decrypt-browser@0.1.0-preview.4...@aws-crypto/decrypt-browser@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [0.1.0-preview.4](/compare/@aws-crypto/decrypt-browser@0.1.0-preview.3...@aws-crypto/decrypt-browser@0.1.0-preview.4) (2019-09-20)

**Note:** Version bump only for package @aws-crypto/decrypt-browser





# [0.1.0-preview.3](/compare/@aws-crypto/decrypt-browser@0.1.0-preview.2...@aws-crypto/decrypt-browser@0.1.0-preview.3) (2019-08-08)


### Bug Fixes

* encrypt/decrypt interface should be the same (#189) ff78f94, closes #189 #182
* Encryption Context changes (#148) 5a7e9ca, closes #148 #54

### BREAKING CHANGES

* `decrypt` now returns `{plaintext: Uint8Array, messageHeader: MessageHeader}`
instead of `{clearMessage: Uint8Array, messageHeader: MessageHeader}`.



# [0.1.0-preview.2](/compare/@aws-crypto/decrypt-browser@0.1.0-preview.1...@aws-crypto/decrypt-browser@0.1.0-preview.2) (2019-07-24)


### Bug Fixes

* encrypt/decrypt browser 21d65d0
* sequence number order (#158) b7dc81e, closes #158





# [0.1.0-preview.1](/compare/@aws-crypto/decrypt-browser@0.1.0-preview.0...@aws-crypto/decrypt-browser@0.1.0-preview.1) (2019-06-21)


### Bug Fixes

* package.json files path update (#120) fbc3270, closes #120





# 0.1.0-preview.0 (2019-06-21)


### Bug Fixes

*  footer structure and zero length final frame (#55) 869106b, closes #55
* Default CMM should not be required (#80) 465de6c, closes #80 #44 #70
* dependencies and lint (#75) 5324491, closes #75
* ECDSA signature in the browser (#63) bc04a91, closes #63
* LICENSE file needs date and owner e0f7085
* Update nyc version fcfa3af


### Features

* add client libraries (#89) 24c72da, closes #89
* browser testing code coverage (#111) aacb5b3, closes #111
* export MessageHeader 53cf7b6
* initial commit for decrypt-browser (#15) 3cfa89b, closes #15
* support v2 and v3 AWS SDK-JS (#66) 0706c31, closes #66
