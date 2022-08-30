# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [1.9.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/decrypt-node@1.9.0...@aws-crypto/decrypt-node@1.9.1) (2022-08-30)

**Note:** Version bump only for package @aws-crypto/decrypt-node





# [1.9.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/decrypt-node@1.7.0...@aws-crypto/decrypt-node@1.9.0) (2021-05-27)


### Bug Fixes

* better typing from typescript ([7a32a7e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/7a32a7e793fb4c334a8b1bf5f0747ac8498681b0))
* Boundary condition error in VerifyStream ([#509](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/issues/509)) ([3070b71](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/3070b71f1d1b5f5fd999b5dc8a8e33692cce59f3)), closes [#507](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/issues/507)


### Features

* Improvements to the message decryption process ([#612](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/issues/612)) ([1f09117](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/1f09117a0c08bd42cd1260e1b010d313ee6f5371))





# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/decrypt-node@1.0.5...@aws-crypto/decrypt-node@1.7.0) (2020-09-24)


### Features

* Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))





## [1.0.5](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/decrypt-node@1.0.4...@aws-crypto/decrypt-node@1.0.5) (2020-05-26)


### Bug Fixes

* resource exhaustion from an incomplete encrypted message ([#348](https://github.com/aws/aws-encryption-sdk-javascript/issues/348)) ([8c81013](https://github.com/aws/aws-encryption-sdk-javascript/commit/8c810131986b782c0702da4988b3999279daf2a3))





## [1.0.4](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/decrypt-node@1.0.3...@aws-crypto/decrypt-node@1.0.4) (2020-04-02)

**Note:** Version bump only for package @aws-crypto/decrypt-node





## [1.0.3](/compare/@aws-crypto/decrypt-node@1.0.2...@aws-crypto/decrypt-node@1.0.3) (2020-02-07)


### Bug Fixes

* lerna version maintains package-lock (#235) c901318, closes #235 #234





## [1.0.2](/compare/@aws-crypto/decrypt-node@1.0.1...@aws-crypto/decrypt-node@1.0.2) (2019-11-12)

**Note:** Version bump only for package @aws-crypto/decrypt-node





## [1.0.1](/compare/@aws-crypto/decrypt-node@1.0.0...@aws-crypto/decrypt-node@1.0.1) (2019-10-15)

**Note:** Version bump only for package @aws-crypto/decrypt-node





# [1.0.0](/compare/@aws-crypto/decrypt-node@0.1.0-preview.4...@aws-crypto/decrypt-node@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/decrypt-node





# [0.1.0-preview.4](/compare/@aws-crypto/decrypt-node@0.1.0-preview.3...@aws-crypto/decrypt-node@0.1.0-preview.4) (2019-09-20)


### Bug Fixes

* Zero length frames in old version of Node (#202) c50dfa1, closes #202 #199





# [0.1.0-preview.3](/compare/@aws-crypto/decrypt-node@0.1.0-preview.2...@aws-crypto/decrypt-node@0.1.0-preview.3) (2019-08-08)


### Bug Fixes

* Conditions for materials-management (#185) 7f7228b, closes #185
* Encryption Context changes (#148) 5a7e9ca, closes #148 #54
* maxBodySize can not short circuit on frameLengh (#181) b07a084, closes #181





# [0.1.0-preview.2](/compare/@aws-crypto/decrypt-node@0.1.0-preview.1...@aws-crypto/decrypt-node@0.1.0-preview.2) (2019-07-24)


### Bug Fixes

* encrypt/decrypt node (#133) 896883a, closes #133
* sequence number order (#158) b7dc81e, closes #158


### Features

* Node.js Typescript version dependency (#146) 9dfa857, closes #146 #135 #74





# [0.1.0-preview.1](/compare/@aws-crypto/decrypt-node@0.1.0-preview.0...@aws-crypto/decrypt-node@0.1.0-preview.1) (2019-06-21)


### Bug Fixes

* package.json files path update (#120) fbc3270, closes #120





# 0.1.0-preview.0 (2019-06-21)


### Bug Fixes

*  footer structure and zero length final frame (#55) 869106b, closes #55
* Default CMM should not be required (#80) 465de6c, closes #80 #44 #70
* dependencies and lint (#75) 5324491, closes #75
* LICENSE file needs date and owner e0f7085
* lint and tests (#43) 613c0af, closes #43
* Update nyc version fcfa3af


### Features

* add client libraries (#89) 24c72da, closes #89
* decrypt-node initial commit (#14) 45748c8, closes #14
* export MessageHeader 53cf7b6
* maxBodySize constraint on decrypt (#81) 42908b0, closes #81 #48
