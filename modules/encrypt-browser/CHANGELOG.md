# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [3.0.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.2) (2021-09-08)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





## [3.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.1) (2021-09-07)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





# [3.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





# [2.4.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





## [2.3.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.0...v2.3.1) (2021-07-01)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





# [2.3.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





# [2.2.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/encrypt-browser@2.1.0...@aws-crypto/encrypt-browser@2.2.0) (2021-05-27)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





# [2.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/encrypt-browser@2.0.0...@aws-crypto/encrypt-browser@2.1.0) (2021-02-04)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





# [2.0.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/encrypt-browser@1.7.0...@aws-crypto/encrypt-browser@2.0.0) (2020-09-25)


* feat!: Updates to the AWS Encryption SDK. ([0a8a581](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/0a8a581ab7c058735310016b819caaec6868c0a7))


### BREAKING CHANGES

* AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html





# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/encrypt-browser@1.1.2...@aws-crypto/encrypt-browser@1.7.0) (2020-09-24)


### Features

* Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))





## [1.1.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/encrypt-browser@1.1.1...@aws-crypto/encrypt-browser@1.1.2) (2020-05-26)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





## [1.1.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/encrypt-browser@1.1.0...@aws-crypto/encrypt-browser@1.1.1) (2020-04-02)


### Bug Fixes

* The final frame can not be larger than the Frame Length ([#281](https://github.com/aws/aws-encryption-sdk-javascript/issues/281)) ([3dd6f43](https://github.com/aws/aws-encryption-sdk-javascript/commit/3dd6f438c6cf2b456a8a92d5d9821503d016bc90))





# [1.1.0](/compare/@aws-crypto/encrypt-browser@1.0.3...@aws-crypto/encrypt-browser@1.1.0) (2020-02-07)


### Features

* Update version of dependencies (#241) cf404a4, closes #241





## [1.0.3](/compare/@aws-crypto/encrypt-browser@1.0.2...@aws-crypto/encrypt-browser@1.0.3) (2020-02-07)


### Bug Fixes

* lerna version maintains package-lock (#235) c901318, closes #235 #234





## [1.0.2](/compare/@aws-crypto/encrypt-browser@1.0.1...@aws-crypto/encrypt-browser@1.0.2) (2019-11-12)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





## [1.0.1](/compare/@aws-crypto/encrypt-browser@1.0.0...@aws-crypto/encrypt-browser@1.0.1) (2019-10-15)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





# [1.0.0](/compare/@aws-crypto/encrypt-browser@0.1.0-preview.4...@aws-crypto/encrypt-browser@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/encrypt-browser





# [0.1.0-preview.4](/compare/@aws-crypto/encrypt-browser@0.1.0-preview.3...@aws-crypto/encrypt-browser@0.1.0-preview.4) (2019-09-20)


### Bug Fixes

* Encrypt name to result (#211) 03061d1, closes #211

### BREAKING CHANGES

* `encrypt` now returns `{result: Uint8Array, messageHeader: MessageHeader}`
instead of `{ciphertext: Uint8Array, messageHeader: MessageHeader}`.



# [0.1.0-preview.3](/compare/@aws-crypto/encrypt-browser@0.1.0-preview.2...@aws-crypto/encrypt-browser@0.1.0-preview.3) (2019-08-08)


### Bug Fixes

* encrypt/decrypt interface should be the same (#189) ff78f94, closes #189 #182
* Encryption Context changes (#148) 5a7e9ca, closes #148 #54
* framLength is not passed to the CMM (#190) b60f653, closes #190 #161


### BREAKING CHANGES

* `encrypt` now returns `{ciphertext: Uint8Array, messageHeader: MessageHeader}`
instead of `{cipherMessage: Uint8Array, messageHeader: MessageHeader}`.



# [0.1.0-preview.2](/compare/@aws-crypto/encrypt-browser@0.1.0-preview.1...@aws-crypto/encrypt-browser@0.1.0-preview.2) (2019-07-24)


### Bug Fixes

* browser framed encryption (#156) a2f2ed9, closes #156 #155
* encrypt/decrypt browser 21d65d0
* frame length can not be 0 (#149) dc1f92e, closes #149 #129





# [0.1.0-preview.1](/compare/@aws-crypto/encrypt-browser@0.1.0-preview.0...@aws-crypto/encrypt-browser@0.1.0-preview.1) (2019-06-21)


### Bug Fixes

* package.json files path update (#120) fbc3270, closes #120





# 0.1.0-preview.0 (2019-06-21)


### Bug Fixes

*  footer structure and zero length final frame (#55) 869106b, closes #55
* Default CMM should not be required (#80) 465de6c, closes #80 #44 #70
* dependencies and lint (#75) 5324491, closes #75
* ECDSA signature in the browser (#63) bc04a91, closes #63
* frameLength should alway be respected (#79) ab2dba8, closes #79 #42
* LICENSE file needs date and owner e0f7085
* Update nyc version fcfa3af


### Features

* browser testing code coverage (#111) aacb5b3, closes #111
* export MessageHeader 53cf7b6
* initial commit for encrypt-browser (#13) 7a14870, closes #13
* Message ID should be defined in serialize (#88) cc167c5, closes #88
