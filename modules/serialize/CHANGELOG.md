# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [3.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)

**Note:** Version bump only for package @aws-crypto/serialize





# [2.4.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package @aws-crypto/serialize





## [2.3.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.0...v2.3.1) (2021-07-01)


### Bug Fixes

* der2raw sLength is s byte length ([#634](https://github.com/aws/aws-encryption-sdk-javascript/issues/634)) ([46cd178](https://github.com/aws/aws-encryption-sdk-javascript/commit/46cd1789744064679a294f49c21ec05f95057b82))





# [2.3.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)

**Note:** Version bump only for package @aws-crypto/serialize





# [2.2.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/serialize@2.1.0...@aws-crypto/serialize@2.2.0) (2021-05-27)


### Bug Fixes

* decoded encryption context is frozen ([#598](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/issues/598)) ([b6d1fe7](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/b6d1fe759668073ae5c59f190ddae6befec4f77f))





# [2.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/serialize@2.0.0...@aws-crypto/serialize@2.1.0) (2021-02-04)

**Note:** Version bump only for package @aws-crypto/serialize





# [2.0.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/serialize@1.7.0...@aws-crypto/serialize@2.0.0) (2020-09-25)


* feat!: Updates to the AWS Encryption SDK. ([0a8a581](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/0a8a581ab7c058735310016b819caaec6868c0a7))


### BREAKING CHANGES

* AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html





# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/serialize@1.0.4...@aws-crypto/serialize@1.7.0) (2020-09-24)


### Features

* Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))





## [1.0.4](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/serialize@1.0.3...@aws-crypto/serialize@1.0.4) (2020-05-26)


### Bug Fixes

* nonFramed maximum content length ([#316](https://github.com/aws/aws-encryption-sdk-javascript/issues/316)) ([9c2f26c](https://github.com/aws/aws-encryption-sdk-javascript/commit/9c2f26c3d5203b8372f127423121f6e194550c23))
* resource exhaustion from an incomplete encrypted message ([#348](https://github.com/aws/aws-encryption-sdk-javascript/issues/348)) ([8c81013](https://github.com/aws/aws-encryption-sdk-javascript/commit/8c810131986b782c0702da4988b3999279daf2a3))





## [1.0.3](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/serialize@1.0.2...@aws-crypto/serialize@1.0.3) (2020-04-02)


### Bug Fixes

* The final frame can not be larger than the Frame Length ([#281](https://github.com/aws/aws-encryption-sdk-javascript/issues/281)) ([3dd6f43](https://github.com/aws/aws-encryption-sdk-javascript/commit/3dd6f438c6cf2b456a8a92d5d9821503d016bc90))





## [1.0.2](/compare/@aws-crypto/serialize@1.0.1...@aws-crypto/serialize@1.0.2) (2020-02-07)


### Bug Fixes

* lerna version maintains package-lock (#235) c901318, closes #235 #234





## [1.0.1](/compare/@aws-crypto/serialize@1.0.0...@aws-crypto/serialize@1.0.1) (2019-10-15)

**Note:** Version bump only for package @aws-crypto/serialize





# [1.0.0](/compare/@aws-crypto/serialize@0.1.0-preview.4...@aws-crypto/serialize@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/serialize





# [0.1.0-preview.4](/compare/@aws-crypto/serialize@0.1.0-preview.3...@aws-crypto/serialize@0.1.0-preview.4) (2019-09-20)


### Bug Fixes

* BYTES_PER_KEY value (#193) d3118d7, closes #193
* plaintextLength must be enforced (#213) 1788d25, closes #213
* prototype inheritance bug in decodeEncryptionContext (#216) 6945eef, closes #216
* updating readElement to match underlying data structure (#215) b59855e, closes #215
* version and type are required by the message format (#217) de30b36, closes #217 #209





# [0.1.0-preview.3](/compare/@aws-crypto/serialize@0.1.0-preview.2...@aws-crypto/serialize@0.1.0-preview.3) (2019-08-08)

**Note:** Version bump only for package @aws-crypto/serialize





# [0.1.0-preview.2](/compare/@aws-crypto/serialize@0.1.0-preview.1...@aws-crypto/serialize@0.1.0-preview.2) (2019-07-24)


### Bug Fixes

* Add tests for signature info (#134) c9b0318, closes #134
* browser encrypt signature encoding (#157) 8e33d7d, closes #157 #154





# [0.1.0-preview.1](/compare/@aws-crypto/serialize@0.1.0-preview.0...@aws-crypto/serialize@0.1.0-preview.1) (2019-06-21)


### Bug Fixes

* package.json files path update (#120) fbc3270, closes #120





# 0.1.0-preview.0 (2019-06-21)


### Bug Fixes

*  footer structure and zero length final frame (#55) 869106b, closes #55
* dependencies and lint (#75) 5324491, closes #75
* ECDSA signature in the browser (#63) bc04a91, closes #63
* EncryptedDataKey providerInfo (#36) 5da3b86, closes #36
* frameLength should alway be respected (#79) ab2dba8, closes #79 #42
* LICENSE file needs date and owner e0f7085
* serializeEncryptedDataKey (#53) ddc2a79, closes #53
* Update nyc version fcfa3af


### Features

* cacheing material management (#38) 7dd6532, closes #38
* initial commit for serialize (#6) 8da226f, closes #6
* Message ID should be defined in serialize (#88) cc167c5, closes #88
* raw AES keyring helpers (#37) 1a5080f, closes #37
* support v2 and v3 AWS SDK-JS (#66) 0706c31, closes #66
