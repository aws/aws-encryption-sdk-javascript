# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

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
