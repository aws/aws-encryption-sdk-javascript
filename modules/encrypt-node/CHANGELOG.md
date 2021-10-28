# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [3.0.3](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.2...v3.0.3) (2021-09-21)

**Note:** Version bump only for package @aws-crypto/encrypt-node





## [3.0.2](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.2) (2021-09-08)

**Note:** Version bump only for package @aws-crypto/encrypt-node





## [3.0.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v3.0.0...v3.0.1) (2021-09-07)

**Note:** Version bump only for package @aws-crypto/encrypt-node





# [3.0.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.4.0...v3.0.0) (2021-07-14)

**Note:** Version bump only for package @aws-crypto/encrypt-node





# [2.4.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.1...v2.4.0) (2021-07-13)

**Note:** Version bump only for package @aws-crypto/encrypt-node





## [2.3.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.3.0...v2.3.1) (2021-07-01)

**Note:** Version bump only for package @aws-crypto/encrypt-node





# [2.3.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/v2.2.1...v2.3.0) (2021-06-16)

**Note:** Version bump only for package @aws-crypto/encrypt-node





# [2.2.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/encrypt-node@2.1.0...@aws-crypto/encrypt-node@2.2.0) (2021-05-27)

**Note:** Version bump only for package @aws-crypto/encrypt-node





# [2.1.0](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/encrypt-node@2.0.0...@aws-crypto/encrypt-node@2.1.0) (2021-02-04)


### Bug Fixes

* better typing from typescript ([9b53325](https://github.com/aws/aws-encryption-sdk-javascript/commit/9b5332542c1293b66d3f35587851802864e531b4))





# [2.0.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/encrypt-node@1.7.0...@aws-crypto/encrypt-node@2.0.0) (2020-09-25)


* feat!: Updates to the AWS Encryption SDK. ([0a8a581](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/0a8a581ab7c058735310016b819caaec6868c0a7))


### BREAKING CHANGES

* AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html





# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/encrypt-node@1.0.5...@aws-crypto/encrypt-node@1.7.0) (2020-09-24)


### Features

* Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))





## [1.0.5](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/encrypt-node@1.0.4...@aws-crypto/encrypt-node@1.0.5) (2020-05-26)

**Note:** Version bump only for package @aws-crypto/encrypt-node





## [1.0.4](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/encrypt-node@1.0.3...@aws-crypto/encrypt-node@1.0.4) (2020-04-02)


### Bug Fixes

* The final frame can not be larger than the Frame Length ([#281](https://github.com/aws/aws-encryption-sdk-javascript/issues/281)) ([3dd6f43](https://github.com/aws/aws-encryption-sdk-javascript/commit/3dd6f438c6cf2b456a8a92d5d9821503d016bc90))





## [1.0.3](/compare/@aws-crypto/encrypt-node@1.0.2...@aws-crypto/encrypt-node@1.0.3) (2020-02-07)


### Bug Fixes

* lerna version maintains package-lock (#235) c901318, closes #235 #234





## [1.0.2](/compare/@aws-crypto/encrypt-node@1.0.1...@aws-crypto/encrypt-node@1.0.2) (2019-11-12)

**Note:** Version bump only for package @aws-crypto/encrypt-node





## [1.0.1](/compare/@aws-crypto/encrypt-node@1.0.0...@aws-crypto/encrypt-node@1.0.1) (2019-10-15)

**Note:** Version bump only for package @aws-crypto/encrypt-node





# [1.0.0](/compare/@aws-crypto/encrypt-node@0.1.0-preview.4...@aws-crypto/encrypt-node@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/encrypt-node





# [0.1.0-preview.4](/compare/@aws-crypto/encrypt-node@0.1.0-preview.3...@aws-crypto/encrypt-node@0.1.0-preview.4) (2019-09-20)


### Bug Fixes

* Encrypt name to result (#211) 03061d1, closes #211
* plaintextLength must be enforced (#213) 1788d25, closes #213

### BREAKING CHANGES

* `encrypt` now returns `{result: Uint8Array, messageHeader: MessageHeader}`
instead of `{ciphertext: Uint8Array, messageHeader: MessageHeader}`.
*  `encrypt` and `encryptStream` will now throw
if the caller tries to encrypt more data than `plaintextLength`.


# [0.1.0-preview.3](/compare/@aws-crypto/encrypt-node@0.1.0-preview.2...@aws-crypto/encrypt-node@0.1.0-preview.3) (2019-08-08)


### Bug Fixes

* Encryption Context changes (#148) 5a7e9ca, closes #148 #54
* framLength is not passed to the CMM (#190) b60f653, closes #190 #161

### BREAKING CHANGES

* `encrypt` and `encryptStream` now expect the encryption context 
to be passed as `encryptionContext` instead of `context`.

# [0.1.0-preview.2](/compare/@aws-crypto/encrypt-node@0.1.0-preview.1...@aws-crypto/encrypt-node@0.1.0-preview.2) (2019-07-24)


### Bug Fixes

* browser framed encryption (#156) a2f2ed9, closes #156 #155
* encrypt/decrypt node (#133) 896883a, closes #133
* frame length can not be 0 (#149) dc1f92e, closes #149 #129


### Features

* Node.js Typescript version dependency (#146) 9dfa857, closes #146 #135 #74





# [0.1.0-preview.1](/compare/@aws-crypto/encrypt-node@0.1.0-preview.0...@aws-crypto/encrypt-node@0.1.0-preview.1) (2019-06-21)


### Bug Fixes

* package.json files path update (#120) fbc3270, closes #120





# 0.1.0-preview.0 (2019-06-21)


### Bug Fixes

*  footer structure and zero length final frame (#55) 869106b, closes #55
* Default CMM should not be required (#80) 465de6c, closes #80 #44 #70
* dependencies and lint (#75) 5324491, closes #75
* frameLength should alway be respected (#79) ab2dba8, closes #79 #42
* LICENSE file needs date and owner e0f7085
* lint and tests (#43) 613c0af, closes #43
* push is private, write is public (#65) c36b9b3, closes #65
* Update nyc version fcfa3af
* use BufferEncoding (#61) 33175b2, closes #61


### Features

* add client libraries (#89) 24c72da, closes #89
* encrypt-node initial commit (#12) 8c2607b, closes #12
* export MessageHeader 53cf7b6
* export MessageHeader (#64) 22e29ce, closes #64
* Message ID should be defined in serialize (#88) cc167c5, closes #88
