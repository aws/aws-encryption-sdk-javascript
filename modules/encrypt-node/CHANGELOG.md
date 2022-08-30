# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [1.9.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/encrypt-node@1.9.0...@aws-crypto/encrypt-node@1.9.1) (2022-08-30)

**Note:** Version bump only for package @aws-crypto/encrypt-node





# [1.9.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/encrypt-node@1.7.0...@aws-crypto/encrypt-node@1.9.0) (2021-05-27)


### Bug Fixes

* better typing from typescript ([7a32a7e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/7a32a7e793fb4c334a8b1bf5f0747ac8498681b0))


### Features

* Improvements to the message decryption process ([#612](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/issues/612)) ([1f09117](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/1f09117a0c08bd42cd1260e1b010d313ee6f5371))





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
