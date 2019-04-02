/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import {
  EncryptedDataKey,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  SignatureKey,
  VerificationKey,
  WebCryptoAlgorithmSuite,
  KeyringTraceFlag
} from '../src'
import {
  decorateCryptographicMaterial,
  decorateEncryptionMaterial,
  decorateDecryptionMaterial,
  decorateWebCryptoMaterial,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  subtleFunctionForMaterial,
  keyUsageForMaterial,
  isValidCryptoKey,
  isCryptoKey
} from '../src/cryptographic_material'

describe('decorateCryptographicMaterial', () => {
  it('will decorate', () => {
    const test = decorateCryptographicMaterial((<any>{}), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    expect(test).to.haveOwnProperty('setUnencryptedDataKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('getUnencryptedDataKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('zeroUnencryptedDataKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('hasUnencryptedDataKey').and.to.equal(false)
  })

  it('set, inspect, get works', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(dataKey, { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY })
    expect(test.hasUnencryptedDataKey).to.equal(true)
    expect(test.unencryptedDataKeyLength).to.equal(dataKey.byteLength)
    expect(test.getUnencryptedDataKey()).to.deep.equal(dataKey)
  })

  it('zeroing out the unencrypted data key', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(dataKey, { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY })
    test.zeroUnencryptedDataKey()
    expect(test.hasUnencryptedDataKey).to.equal(false)
    expect(dataKey).to.deep.equal(new Uint8Array(suite.keyLengthBytes).fill(0))
  })

  it('Precondition: The data key length must agree with algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    const dataKey = new Uint8Array(suite.keyLengthBytes - 1).fill(1)
    expect(() => test.setUnencryptedDataKey(dataKey)).to.throw()
  })

  it('Precondition: unencryptedDataKey must not be Zeroed out.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(dataKey, { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY })
    test.zeroUnencryptedDataKey()
    expect(() => test.getUnencryptedDataKey()).to.throw()
    expect(() => test.unencryptedDataKeyLength).to.throw()
  })

  it('Precondition: unencryptedDataKey must be set before we can return it.', () => {
    const test: any = decorateCryptographicMaterial((<any>{}), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    expect(() => test.getUnencryptedDataKey()).to.throw()
  })

  it('Precondition: The unencryptedDataKey must be set to have a length.', () => {
    const test: any = decorateCryptographicMaterial((<any>{}), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    expect(() => test.unencryptedDataKeyLength).to.throw()
  })

  it('Precondition: The unencryptedDataKey must be set to be zeroed.', () => {
    const test: any = decorateCryptographicMaterial((<any>{}), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    expect(() => test.zeroUnencryptedDataKey()).to.throw()
  })

  it('Precondition: dataKey must be Binary Data', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    expect(() => test.setUnencryptedDataKey('')).to.throw()
  })

  it('Precondition: unencryptedDataKey must not be set.  Modifying the unencryptedDataKey is denied', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(dataKey, { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY })
    expect(() => test.setUnencryptedDataKey(dataKey)).to.throw()
  })

  it('Precondition: The unencryptedDataKey must not have been modified.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const material = decorateCryptographicMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    material.setUnencryptedDataKey(dataKey, { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY })
    const test = material.getUnencryptedDataKey()
    test[0] = 12
    expect(() => material.getUnencryptedDataKey()).to.throw()
  })
})

describe('decorateEncryptionMaterial', () => {
  it('will decorate', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [] }))
    expect(test).to.haveOwnProperty('addEncryptedDataKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('setSignatureKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('encryptedDataKeys').and.to.be.a('array').with.lengthOf(0)
    expect(test).to.haveOwnProperty('signatureKey').and.to.equal(undefined)
  })

  it('add EncryptedDataKey', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    const edk = new EncryptedDataKey({ providerId: 'p', providerInfo: 'p', encryptedDataKey: new Uint8Array(3) })
    test.addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    expect(test.encryptedDataKeys).to.have.length(1)
    expect(test.encryptedDataKeys[0] === edk).to.equal(true)
  })

  it('add SignatureKey', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    const key = new SignatureKey(new Uint8Array(3), new Uint8Array(3), suite)
    test.setSignatureKey(key)
    expect(test.signatureKey === key).to.equal(true)
  })

  it('Precondition: If a data key has not already been generated, there must be no EDKs.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const edk = new EncryptedDataKey({ providerId: 'p', providerInfo: 'p', encryptedDataKey: new Uint8Array(3) })
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: false }))
    expect(() => test.addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)).to.throw()
  })

  it('Precondition: Edk must be EncryptedDataKey', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const edk: any = {}
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    expect(() => test.addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)).to.throw()
  })

  it('Precondition: The SignatureKey stored must agree with the algorithm specification.', () => {
    const suiteWithSig = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const key = new SignatureKey(new Uint8Array(3), new Uint8Array(3), suiteWithSig)
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: signatureKey must not be set.  Modifying the signatureKey is denied.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const key = new SignatureKey(new Uint8Array(3), new Uint8Array(3), suite)
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    test.setSignatureKey(key)
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: key must be a SignatureKey.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const key : any = {}
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: The SignatureKey requested must agree with the algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateEncryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    expect(() => test.signatureKey).to.throw()
  })
})

describe('decorateDecryptionMaterial', () => {
  it('will decorate', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test: any = decorateDecryptionMaterial((<any>{ suite, keyringTrace: [] }))
    expect(test).to.haveOwnProperty('setVerificationKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('verificationKey').and.to.equal(undefined)
  })

  it('add VerificationKey', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateDecryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    const key = new VerificationKey(new Uint8Array(3), suite)
    test.setVerificationKey(key)
    expect(test.verificationKey === key).to.equal(true)
  })

  it('Precondition: The VerificationKey stored must agree with the algorithm specification.', () => {
    const suiteWithSig = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const key = new VerificationKey(new Uint8Array(3), suiteWithSig)
    const test: any = decorateDecryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: verificationKey must not be set.  Modifying the verificationKey is denied.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const key = new VerificationKey(new Uint8Array(3), suite)
    const test: any = decorateDecryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    test.setVerificationKey(key)
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: key must be a VerificationKey.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const key : any = {}
    const test: any = decorateDecryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: The VerificationKey requested must agree with the algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateDecryptionMaterial((<any>{ suite, keyringTrace: [], hasUnencryptedDataKey: true }))
    expect(() => test.verificationKey).to.throw()
  })
})

describe('decorateWebCryptoMaterial', () => {
  it('add CryptoKey', () => {
    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateWebCryptoMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
    const key: any = { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: false }
    const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
    test.setCryptoKey(key, trace)
    expect(test.cryptoKey === key).to.equal(true)
    expect(test.hasCryptoKey).to.equal(true)
  })

  it('add MixedBackendCryptoKey', () => {
    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateWebCryptoMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
    const key: any = { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: false }
    const mixedKey: any = { zeroByteCryptoKey: key, nonZeroByteCryptoKey: key }
    const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
    test.setCryptoKey(mixedKey, trace)
    expect(test.cryptoKey !== mixedKey).to.equal(true)
    expect(test.hasCryptoKey).to.equal(true)
    expect(test.cryptoKey.zeroByteCryptoKey === mixedKey.zeroByteCryptoKey).to.equal(true)
    expect(test.cryptoKey.nonZeroByteCryptoKey === mixedKey.nonZeroByteCryptoKey).to.equal(true)
    expect(Object.isFrozen(test.cryptoKey)).to.equal(true)
  })

  it('Precondition: The cryptoKey must be set before we can return it.', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}), KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
    expect(() => test.cryptoKey).to.throw()
  })

  it('Precondition: cryptoKey must not be set.  Modifying the cryptoKey is denied', () => {
    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateWebCryptoMaterial((<any>{ suite, keyringTrace: [] }), KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
    const key: any = { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: false }
    const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
    test.setCryptoKey(key, trace)
    expect(() => test.setCryptoKey(key, trace)).to.throw()
  })

  it('Precondition: The CryptoKey must match the algorithm suite specification.', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}), KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
    const key: any = { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: true }
    const key1: any = { zeroByteCryptoKey: { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: true }, nonZeroByteCryptoKey: { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: false } }
    const key2: any = { zeroByteCryptoKey: { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: false }, nonZeroByteCryptoKey: { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: true } }
    const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
    expect(() => test.setCryptoKey(key, trace)).to.throw()
    expect(() => test.setCryptoKey(key1, trace)).to.throw()
    expect(() => test.setCryptoKey(key2, trace)).to.throw()
  })

  it('Precondition: dataKey must be a supported type.', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}), KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
    const key: any = {}
    const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
    expect(() => test.setCryptoKey(key, trace)).to.throw()
  })
})

describe('decorateWebCryptoMaterial:Helpers', () => {
  describe('subtleFunctionForMaterial', () => {
    it('WebCryptoDecryptionMaterial is decrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
      const material = new WebCryptoDecryptionMaterial(suite)
      expect(subtleFunctionForMaterial(material)).to.equal('decrypt')
    })

    it('WebCryptoEncryptionMaterial is encrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
      const material = new WebCryptoEncryptionMaterial(suite)
      expect(subtleFunctionForMaterial(material)).to.equal('encrypt')
    })
    it('unsupported', () => {
      const material = {} as any
      expect(() => subtleFunctionForMaterial(material)).to.throw()
    })
  })

  describe('keyUsageForMaterial', () => {
    it('ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 is deriveKey', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
      const material = new WebCryptoDecryptionMaterial(suite)
      expect(keyUsageForMaterial(material)).to.equal('deriveKey')
    })

    it('ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 is decrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
      const material = new WebCryptoEncryptionMaterial(suite)
      expect(keyUsageForMaterial(material)).to.equal('deriveKey')
    })

    it('WebCryptoDecryptionMaterial is decrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
      const material = new WebCryptoDecryptionMaterial(suite)
      expect(keyUsageForMaterial(material)).to.equal('decrypt')
    })

    it('WebCryptoEncryptionMaterial is encrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
      const material = new WebCryptoEncryptionMaterial(suite)
      expect(keyUsageForMaterial(material)).to.equal('encrypt')
    })

    it('unsupported', () => {
      const material = {} as any
      expect(() => keyUsageForMaterial(material)).to.throw()
    })
  })

  it('isCryptoKey', () => {
    const key: any = { type: 'secret', algorithm: { name: 'HKDF' }, usages: ['deriveKey'], extractable: false }
    expect(isCryptoKey(key)).to.equal(true)
  })

  describe('isValidCryptoKey', () => {
    it('Suite with KDF is valid for both the derivable key and the derived key', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
      const material = new WebCryptoEncryptionMaterial(suite)
      const keyKdf: any = { type: 'secret', algorithm: { name: suite.kdf }, usages: ['deriveKey'], extractable: false }
      const deriveKey: any = { type: 'secret', algorithm: { name: suite.encryption, length: suite.keyLength }, usages: ['encrypt'], extractable: false }
      expect(isValidCryptoKey(keyKdf, material)).to.equal(true)
      expect(isValidCryptoKey(deriveKey, material)).to.equal(true)
    })

    it('Suite without the KDF is only derivable with the key', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
      const material = new WebCryptoEncryptionMaterial(suite)
      const keyKdf: any = { type: 'secret', algorithm: { name: suite.kdf }, usages: ['deriveKey'], extractable: false }
      const key: any = { type: 'secret', algorithm: { name: suite.encryption, length: suite.keyLength }, usages: ['encrypt'], extractable: false }
      expect(isValidCryptoKey(keyKdf, material)).to.equal(false)
      expect(isValidCryptoKey(key, material)).to.equal(true)
    })
    it('only type === secret is valid', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
      const material = new WebCryptoEncryptionMaterial(suite)
      const key: any = { type: 'private', algorithm: { name: suite.encryption, length: suite.keyLength }, usages: ['encrypt'], extractable: false }
      expect(isValidCryptoKey(key, material)).to.equal(false)
    })

    it('length must match', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
      const material = new WebCryptoEncryptionMaterial(suite)
      const key: any = { type: 'secret', algorithm: { name: suite.encryption, length: suite.keyLength - 1 }, usages: ['encrypt'], extractable: false }
      expect(isValidCryptoKey(key, material)).to.equal(false)
    })

    it('can not be extractable', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
      const material = new WebCryptoEncryptionMaterial(suite)
      const key: any = { type: 'secret', algorithm: { name: suite.encryption, length: suite.keyLength }, usages: ['encrypt'], extractable: true }
      expect(isValidCryptoKey(key, material)).to.equal(false)
    })

    it('usage must match', () => {
      const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
      const material = new WebCryptoEncryptionMaterial(suite)
      const key: any = { type: 'secret', algorithm: { name: suite.encryption, length: suite.keyLength }, usages: ['decrypt'], extractable: false }
      expect(isValidCryptoKey(key, material)).to.equal(false)
    })
  })
})

describe('NodeEncryptionMaterial', () => {
  const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
  const test: any = new NodeEncryptionMaterial(suite)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(NodeAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(NodeAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: NodeEncryptionMaterial suite must be NodeAlgorithmSuite.', () => {
    const suite: any = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => new NodeEncryptionMaterial(suite)).to.throw()
  })
})

describe('NodeDecryptionMaterial', () => {
  const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
  const test: any = new NodeDecryptionMaterial(suite)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(NodeAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(NodeAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: NodeDecryptionMaterial suite must be NodeAlgorithmSuite.', () => {
    const suite: any = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => new NodeDecryptionMaterial(suite)).to.throw()
  })
})

describe('WebCryptoEncryptionMaterial', () => {
  const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
  const test: any = new WebCryptoEncryptionMaterial(suite)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(WebCryptoAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(WebCryptoAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: WebCryptoEncryptionMaterial suite must be WebCryptoAlgorithmSuite.', () => {
    const suite: any = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => new WebCryptoEncryptionMaterial(suite)).to.throw()
  })
})

describe('WebCryptoDecryptionMaterial', () => {
  const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
  const test: any = new WebCryptoDecryptionMaterial(suite)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(WebCryptoAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(WebCryptoAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: WebCryptoDecryptionMaterial suite must be WebCryptoAlgorithmSuite.', () => {
    const suite: any = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => new WebCryptoDecryptionMaterial(suite)).to.throw()
  })
})
