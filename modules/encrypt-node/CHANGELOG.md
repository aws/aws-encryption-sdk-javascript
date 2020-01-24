# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

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
