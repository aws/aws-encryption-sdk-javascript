# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [1.9.1](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management@1.9.0...@aws-crypto/material-management@1.9.1) (2022-08-30)

**Note:** Version bump only for package @aws-crypto/material-management





# [1.9.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/material-management@1.7.0...@aws-crypto/material-management@1.9.0) (2021-05-27)


### Features

* Improvements to the message decryption process ([#612](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/issues/612)) ([1f09117](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/1f09117a0c08bd42cd1260e1b010d313ee6f5371))





# [1.7.0](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/compare/@aws-crypto/material-management@1.0.4...@aws-crypto/material-management@1.7.0) (2020-09-24)


### Bug Fixes

* Update types for newer typescript versions ([#394](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/issues/394)) ([3069c63](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/3069c631e7b896e7b55b2b0aa1fa12a0a6413abf))


### Features

* Updates to the AWS Encryption SDK. ([748be9e](https://github.com/aws/private-aws-encryption-sdk-javascript-staging/commit/748be9e1799d999a350e9cafbf902d43aeab0aa5))





## [1.0.4](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management@1.0.3...@aws-crypto/material-management@1.0.4) (2020-05-26)


### Bug Fixes

* add asserts to `needs` ([#327](https://github.com/aws/aws-encryption-sdk-javascript/issues/327)) ([c103fa4](https://github.com/aws/aws-encryption-sdk-javascript/commit/c103fa4cf58c89a1a9b57a70744a92e23d923c74))





## [1.0.3](https://github.com/aws/aws-encryption-sdk-javascript/compare/@aws-crypto/material-management@1.0.2...@aws-crypto/material-management@1.0.3) (2020-04-02)


### Bug Fixes

* Duplicate `’algorithm’` check ([1b876dc](https://github.com/aws/aws-encryption-sdk-javascript/commit/1b876dc53fc539306fd8264e166e8f5cee1a1c0b))
* for MSRCrypto 1.6.0 ([cf7e389](https://github.com/aws/aws-encryption-sdk-javascript/commit/cf7e3895aa57b78f89c1c7ec541724f7fe9e6616))
* Kdf keys should have an algorithm name of ‘HKDF’ ([6100d1d](https://github.com/aws/aws-encryption-sdk-javascript/commit/6100d1deeb60a6d4ef80efd12c258b5ebc0cef1d))





## [1.0.2](/compare/@aws-crypto/material-management@1.0.1...@aws-crypto/material-management@1.0.2) (2020-02-07)


### Bug Fixes

* lerna version maintains package-lock (#235) c901318, closes #235 #234





## [1.0.1](/compare/@aws-crypto/material-management@1.0.0...@aws-crypto/material-management@1.0.1) (2019-10-15)


### Bug Fixes

* eval in portableTimingSafeEqual (#227) edd41f2, closes #227





# [1.0.0](/compare/@aws-crypto/material-management@0.2.0-preview.4...@aws-crypto/material-management@1.0.0) (2019-10-01)

**Note:** Version bump only for package @aws-crypto/material-management





# [0.2.0-preview.4](/compare/@aws-crypto/material-management@0.2.0-preview.3...@aws-crypto/material-management@0.2.0-preview.4) (2019-09-20)


### Bug Fixes

* Better error messageing (#212) 7198100, closes #212 #152
* Better timingSafeEqual definition (#203) 12d1661, closes #203
* KeyringTraceFlag requirements and data key caching (#210) 7dfa1ae, closes #210


### Features

* Remove unencryptedDataKeyLength (#201) bd160c0, closes #201
* Suport Node.js crypto KeyObjects (#200) 77ad031, closes #200 #74

### BREAKING CHANGES

* CryptographicMaterial no longer support `unencryptedDataKeyLength`



# [0.2.0-preview.3](/compare/@aws-crypto/material-management@0.2.0-preview.2...@aws-crypto/material-management@0.2.0-preview.3) (2019-08-08)


### Bug Fixes

* Conditions for materials-management (#185) 7f7228b, closes #185
* Encryption Context changes (#148) 5a7e9ca, closes #148 #54
* framLength is not passed to the CMM (#190) b60f653, closes #190 #161
* Multi keyrings should not require a generator (#165) 11ff819, closes #165

### BREAKING CHANGES

* CryptographicMaterial now require `encryptionContext` on creation.
this includes `NodeDecryptionMaterial`, `NodeEncryptionMaterial`,
`WebCryptoEncryptionMaterial`, and `WebCryptoDecryptionMaterial`.
* The Keyring base class no longer accepts `encryptionContext`
for `onDecrypt` and `onEncrypt`.
It now gets this value from the CryptographicMaterial passed.
* The CMM interface now returns CryptographicMaterial
instead of a complex object with material and context.



# [0.2.0-preview.2](/compare/@aws-crypto/material-management@0.2.0-preview.1...@aws-crypto/material-management@0.2.0-preview.2) (2019-07-24)


### Bug Fixes

* 192 bit algorithm suite support in browsers (#131) 8a4d708, closes #131
* Always explicitly catch exceptions. (#132) bf88871, closes #132
* material-management should not export DOM types (#147) 0f4dd7e, closes #147 #137





# [0.2.0-preview.1](/compare/@aws-crypto/material-management@0.2.0-preview.0...@aws-crypto/material-management@0.2.0-preview.1) (2019-06-21)


### Bug Fixes

* package.json files path update (#120) fbc3270, closes #120





# 0.2.0-preview.0 (2019-06-21)


### Bug Fixes

* browser integration (#57) 1285e0e, closes #57
* Browser things for integration module (#56) a2c46c1, closes #56
* Default CMM should not be required (#80) 465de6c, closes #80 #44 #70
* dependencies and lint (#75) 5324491, closes #75
* EncryptedDataKey providerInfo (#36) 5da3b86, closes #36
* LICENSE file needs date and owner e0f7085
* MultiKeyring instanceof (#35) b21aca7, closes #35
* portableTimingSafeEqual may be optimized (#73) 688e81e, closes #73
* signatureCurve property on keys (#98) ba92ebd, closes #98
* Update nyc version fcfa3af


### Features

* cacheing material management (#38) 7dd6532, closes #38
* raw AES keyring helpers (#37) 1a5080f, closes #37
