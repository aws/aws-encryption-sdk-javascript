// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  EncryptedDataKey,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  SignatureKey,
  VerificationKey,
  WebCryptoAlgorithmSuite,
  KeyringTraceFlag,
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
  isCryptoKey,
  unwrapDataKey,
  wrapWithKeyObjectIfSupported,
  supportsKeyObject,
} from '../src/cryptographic_material'

import { createSecretKey } from 'crypto'

describe('decorateCryptographicMaterial', () => {
  it('will decorate', () => {
    const test = decorateCryptographicMaterial(
      {} as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    expect(test)
      .to.haveOwnProperty('setUnencryptedDataKey')
      .and.to.be.a('function')
    expect(test)
      .to.haveOwnProperty('getUnencryptedDataKey')
      .and.to.be.a('function')
    expect(test)
      .to.haveOwnProperty('zeroUnencryptedDataKey')
      .and.to.be.a('function')
    expect(test).to.haveOwnProperty('hasUnencryptedDataKey').and.to.equal(false)
  })

  it('Precondition: setFlag must be in the set of KeyringTraceFlag.SET_FLAGS.', () => {
    expect(() =>
      decorateCryptographicMaterial(
        {} as any,
        KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
      )
    ).to.throw('')
  })

  it('set, inspect, get works', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(new Uint8Array(dataKey), {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
    expect(test.hasUnencryptedDataKey).to.equal(true)
    const udk = unwrapDataKey(test.getUnencryptedDataKey())
    expect(udk).to.deep.equal(dataKey)
  })

  it('zeroing out the unencrypted data key', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    /* This is complicated.
     * Now that I support KeyObjects it is good to pass a copy,
     * i.e. new Uint8Array(dataKey).
     * But in this case, if this is a version of Node.js that does not support KeyObjects
     * passing the dataKey lets me verify that the value memory is really zeroed.
     */
    test.setUnencryptedDataKey(dataKey, {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
    test.zeroUnencryptedDataKey()
    expect(test.hasUnencryptedDataKey).to.equal(false)
    if (!supportsKeyObject) {
      expect(dataKey).to.deep.equal(
        new Uint8Array(suite.keyLengthBytes).fill(0)
      )
    } else {
      // If the environment supports KeyObjects then the udk was wrapped.
      // There is no way to confirm that
    }
  })

  it('Precondition: The data key length must agree with algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes - 1).fill(1)
    expect(() => test.setUnencryptedDataKey(new Uint8Array(dataKey))).to.throw()
  })

  it('Precondition: unencryptedDataKey must not be Zeroed out.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(new Uint8Array(dataKey), {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
    test.zeroUnencryptedDataKey()
    expect(() => test.getUnencryptedDataKey()).to.throw()
  })

  it('Precondition: unencryptedDataKey must be set before we can return it.', () => {
    const test: any = decorateCryptographicMaterial(
      {} as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    expect(() => test.getUnencryptedDataKey()).to.throw()
  })

  it(`Precondition: If the unencryptedDataKey has not been set, it should not be settable later.
      Precondition: If the udkForVerification has not been set, it should not be settable later.`, () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    test.zeroUnencryptedDataKey()
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    // It is very hard to test this perfectly.  However, this tests the spirit.
    expect(() =>
      test.setUnencryptedDataKey(new Uint8Array(dataKey), trace)
    ).to.throw()
  })

  it('Precondition: dataKey must be Binary Data', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    expect(() => test.setUnencryptedDataKey('')).to.throw()
  })

  it('Precondition: unencryptedDataKey must not be set.  Modifying the unencryptedDataKey is denied', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    test.setUnencryptedDataKey(new Uint8Array(dataKey), trace)
    expect(() =>
      test.setUnencryptedDataKey(new Uint8Array(dataKey), trace)
    ).to.throw('unencryptedDataKey has already been set')
  })

  it('Precondition: dataKey should have an ArrayBuffer that *only* stores the key.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(
      new ArrayBuffer(suite.keyLengthBytes + 10),
      5,
      suite.keyLengthBytes
    ).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    expect(() => test.setUnencryptedDataKey(dataKey, trace)).to.throw(
      'Unencrypted Master Key must be an isolated buffer.'
    )
  })

  it('Precondition: Trace must be set, and the flag must indicate that the data key was generated.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    expect(() =>
      test.setUnencryptedDataKey(new Uint8Array(dataKey), {} as any)
    ).to.throw('Malformed KeyringTrace')
  })

  it('Precondition: On set the required KeyringTraceFlag must be set.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX,
    }
    expect(() =>
      test.setUnencryptedDataKey(new Uint8Array(dataKey), trace)
    ).to.throw('Required KeyringTraceFlag not set')
  })

  it('Precondition: Only valid flags are allowed.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags:
        KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY |
        KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    expect(() =>
      test.setUnencryptedDataKey(new Uint8Array(dataKey), trace)
    ).to.throw('Invalid KeyringTraceFlags set.')
  })

  it('Precondition: The unencryptedDataKey must not have been modified.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = decorateCryptographicMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    material.setUnencryptedDataKey(dataKey, {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
    const test = material.getUnencryptedDataKey()
    test[0] = 12
    expect(() => {
      const udk = unwrapDataKey(material.getUnencryptedDataKey())
      if (supportsKeyObject) {
        /* This should NOT be true.
         * If the udk is a KeyObject then the change above was on independent memory.
         * This check follows the code, and is *intended* to fail.
         */
        expect(udk[0]).to.equal(12)
      }
    }).to.throw()
  })
})

describe('decorateEncryptionMaterial', () => {
  it('will decorate', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(test)
      .to.haveOwnProperty('addEncryptedDataKey')
      .and.to.be.a('function')
    expect(test).to.haveOwnProperty('setSignatureKey').and.to.be.a('function')
    expect(test)
      .to.haveOwnProperty('encryptedDataKeys')
      .and.to.be.a('array')
      .with.lengthOf(0)
    expect(test).to.haveOwnProperty('signatureKey').and.to.equal(undefined)
  })

  it('add EncryptedDataKey', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
      hasUnencryptedDataKey: true,
    } as any)
    const edk = new EncryptedDataKey({
      providerId: 'p',
      providerInfo: 'p',
      encryptedDataKey: new Uint8Array(3),
    })
    test.addEncryptedDataKey(
      edk,
      KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
    )
    expect(test.encryptedDataKeys).to.have.length(1)
    expect(test.encryptedDataKeys[0] === edk).to.equal(true)
  })

  it('add SignatureKey', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    const key = new SignatureKey(new Uint8Array(3), new Uint8Array(3), suite)
    test.setSignatureKey(key)
    expect(test.signatureKey === key).to.equal(true)
  })

  it('Precondition: If a data key has not already been generated, there must be no EDKs.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const edk = new EncryptedDataKey({
      providerId: 'p',
      providerInfo: 'p',
      encryptedDataKey: new Uint8Array(3),
    })
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
      hasUnencryptedDataKey: false,
    } as any)
    expect(() =>
      test.addEncryptedDataKey(
        edk,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )
    ).to.throw()
  })

  it('Precondition: Edk must be EncryptedDataKey', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const edk: any = {}
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(() =>
      test.addEncryptedDataKey(
        edk,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )
    ).to.throw()
  })

  it('Precondition: flags must indicate that the key was encrypted.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
      hasUnencryptedDataKey: true,
    } as any)
    const edk = new EncryptedDataKey({
      providerId: 'p',
      providerInfo: 'p',
      encryptedDataKey: new Uint8Array(3),
    })
    expect(() =>
      test.addEncryptedDataKey(
        edk,
        KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
      )
    ).to.throw('Encrypted data key flag must be set.')
  })

  it('Precondition: flags must not include a setFlag or a decrypt flag.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
      hasUnencryptedDataKey: true,
    } as any)
    const edk = new EncryptedDataKey({
      providerId: 'p',
      providerInfo: 'p',
      encryptedDataKey: new Uint8Array(3),
    })
    expect(() =>
      test.addEncryptedDataKey(
        edk,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY |
          KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX
      )
    ).to.throw('Invalid flag for EncryptedDataKey.')
  })

  it('Precondition: The SignatureKey stored must agree with the algorithm specification.', () => {
    const suiteWithSig = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const key = new SignatureKey(
      new Uint8Array(3),
      new Uint8Array(3),
      suiteWithSig
    )
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: signatureKey must not be set.  Modifying the signatureKey is denied.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const key = new SignatureKey(new Uint8Array(3), new Uint8Array(3), suite)
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    test.setSignatureKey(key)
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: key must be a SignatureKey.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const key: any = {}
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: The SignatureKey requested must agree with the algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateEncryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(() => test.signatureKey).to.throw()
  })
})

describe('decorateDecryptionMaterial', () => {
  it('will decorate', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const test: any = decorateDecryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(test)
      .to.haveOwnProperty('setVerificationKey')
      .and.to.be.a('function')
    expect(test).to.haveOwnProperty('verificationKey').and.to.equal(undefined)
  })

  it('add VerificationKey', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateDecryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    const key = new VerificationKey(new Uint8Array(3), suite)
    test.setVerificationKey(key)
    expect(test.verificationKey === key).to.equal(true)
  })

  it('Precondition: The VerificationKey stored must agree with the algorithm specification.', () => {
    const suiteWithSig = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const key = new VerificationKey(new Uint8Array(3), suiteWithSig)
    const test: any = decorateDecryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: verificationKey must not be set.  Modifying the verificationKey is denied.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const key = new VerificationKey(new Uint8Array(3), suite)
    const test: any = decorateDecryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    test.setVerificationKey(key)
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: key must be a VerificationKey.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const key: any = {}
    const test: any = decorateDecryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: The VerificationKey requested must agree with the algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateDecryptionMaterial({
      suite,
      keyringTrace: [],
    } as any)
    expect(() => test.verificationKey).to.throw()
  })
})

describe('decorateWebCryptoMaterial', () => {
  it('add CryptoKey', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateWebCryptoMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    // setCryptoKey uses `zeroUnencryptedDataKey` when setting a cryptoKey *without* a unencrypted data key
    decorateCryptographicMaterial(
      test,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    test.validUsages = ['deriveKey']
    const key: any = {
      type: 'secret',
      algorithm: { name: 'HKDF' },
      usages: ['deriveKey'],
      extractable: false,
    }
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    test.setCryptoKey(key, trace)
    expect(test.getCryptoKey() === key).to.equal(true)
    expect(test.hasCryptoKey).to.equal(true)
    expect(test.hasUnencryptedDataKey).to.equal(false)
  })

  it('add MixedBackendCryptoKey', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateWebCryptoMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    test.validUsages = ['deriveKey']
    // setCryptoKey uses `zeroUnencryptedDataKey` when setting a cryptoKey *without* a unencrypted data key
    decorateCryptographicMaterial(
      test,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    const key: any = {
      type: 'secret',
      algorithm: { name: 'HKDF' },
      usages: ['deriveKey'],
      extractable: false,
    }
    const mixedKey: any = { zeroByteCryptoKey: key, nonZeroByteCryptoKey: key }
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    test.setCryptoKey(mixedKey, trace)
    expect(test.getCryptoKey() !== mixedKey).to.equal(true)
    expect(test.hasCryptoKey).to.equal(true)
    expect(test.hasUnencryptedDataKey).to.equal(false)
    expect(
      test.getCryptoKey().zeroByteCryptoKey === mixedKey.zeroByteCryptoKey
    ).to.equal(true)
    expect(
      test.getCryptoKey().nonZeroByteCryptoKey === mixedKey.nonZeroByteCryptoKey
    ).to.equal(true)
    expect(Object.isFrozen(test.getCryptoKey())).to.equal(true)
  })

  it('Precondition: The cryptoKey must be set before we can return it.', () => {
    const test: any = decorateWebCryptoMaterial(
      {} as any,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    expect(() => test.getCryptoKey()).to.throw()
  })

  it('Precondition: cryptoKey must not be set.  Modifying the cryptoKey is denied', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateWebCryptoMaterial(
      { suite, keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    test.validUsages = ['deriveKey']
    // setCryptoKey uses `zeroUnencryptedDataKey` when setting a cryptoKey *without* a unencrypted data key
    decorateCryptographicMaterial(
      test,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    const key: any = {
      type: 'secret',
      algorithm: { name: 'HKDF' },
      usages: ['deriveKey'],
      extractable: false,
    }
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    test.setCryptoKey(key, trace)
    expect(() => test.setCryptoKey(key, trace)).to.throw()
  })

  it('Precondition: The CryptoKey must match the algorithm suite specification.', () => {
    const test: any = decorateWebCryptoMaterial(
      {} as any,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    const key: any = {
      type: 'secret',
      algorithm: { name: 'HKDF' },
      usages: ['deriveKey'],
      extractable: true,
    }
    const key1: any = {
      zeroByteCryptoKey: {
        type: 'secret',
        algorithm: { name: 'HKDF' },
        usages: ['deriveKey'],
        extractable: true,
      },
      nonZeroByteCryptoKey: {
        type: 'secret',
        algorithm: { name: 'HKDF' },
        usages: ['deriveKey'],
        extractable: false,
      },
    }
    const key2: any = {
      zeroByteCryptoKey: {
        type: 'secret',
        algorithm: { name: 'HKDF' },
        usages: ['deriveKey'],
        extractable: false,
      },
      nonZeroByteCryptoKey: {
        type: 'secret',
        algorithm: { name: 'HKDF' },
        usages: ['deriveKey'],
        extractable: true,
      },
    }
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    expect(() => test.setCryptoKey(key, trace)).to.throw()
    expect(() => test.setCryptoKey(key1, trace)).to.throw()
    expect(() => test.setCryptoKey(key2, trace)).to.throw()
  })

  it('Precondition: If the CryptoKey is the only version, the trace information must be set here.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateWebCryptoMaterial(
      { suite, validUsages: ['deriveKey'], keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    decorateCryptographicMaterial(
      test,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )

    const key: any = {
      type: 'secret',
      algorithm: { name: 'HKDF' },
      usages: ['deriveKey'],
      extractable: false,
    }
    expect(() =>
      test.setCryptoKey(key, {
        keyNamespace: 'k',
        flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
      })
    ).to.throw('Malformed KeyringTrace')
    expect(() =>
      test.setCryptoKey(key, {
        keyName: 'k',
        flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
      })
    ).to.throw('Malformed KeyringTrace')
    expect(() => test.setCryptoKey(key)).to.throw('Malformed KeyringTrace')
  })

  it('Precondition: On setting the CryptoKey the required KeyringTraceFlag must be set.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const test: any = decorateWebCryptoMaterial(
      { suite, validUsages: ['deriveKey'], keyringTrace: [] } as any,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    decorateCryptographicMaterial(
      test,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )

    const key: any = {
      type: 'secret',
      algorithm: { name: 'HKDF' },
      usages: ['deriveKey'],
      extractable: false,
    }
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX,
    }
    expect(() => test.setCryptoKey(key, trace)).to.throw(
      'Required KeyringTraceFlag not set'
    )
  })

  it('Precondition: dataKey must be a supported type.', () => {
    const test: any = decorateWebCryptoMaterial(
      {} as any,
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    const key: any = {}
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    expect(() => test.setCryptoKey(key, trace)).to.throw()
  })
})

describe('decorateWebCryptoMaterial:Helpers', () => {
  describe('subtleFunctionForMaterial', () => {
    it('WebCryptoDecryptionMaterial is decrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
      )
      const material = new WebCryptoDecryptionMaterial(suite, {})
      expect(subtleFunctionForMaterial(material)).to.equal('decrypt')
    })

    it('WebCryptoEncryptionMaterial is encrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      expect(subtleFunctionForMaterial(material)).to.equal('encrypt')
    })
    it('unsupported', () => {
      const material = {} as any
      expect(() => subtleFunctionForMaterial(material)).to.throw()
    })
  })

  describe('keyUsageForMaterial', () => {
    it('ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 is deriveKey', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
      )
      const material = new WebCryptoDecryptionMaterial(suite, {})
      expect(keyUsageForMaterial(material)).to.equal('deriveKey')
    })

    it('ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 is decrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      expect(keyUsageForMaterial(material)).to.equal('deriveKey')
    })

    it('WebCryptoDecryptionMaterial is decrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )
      const material = new WebCryptoDecryptionMaterial(suite, {})
      expect(keyUsageForMaterial(material)).to.equal('decrypt')
    })

    it('WebCryptoEncryptionMaterial is encrypt', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      expect(keyUsageForMaterial(material)).to.equal('encrypt')
    })

    it('unsupported', () => {
      const material = {} as any
      expect(() => keyUsageForMaterial(material)).to.throw()
    })
  })

  it('isCryptoKey', () => {
    const key: any = {
      type: 'secret',
      algorithm: { name: 'HKDF' },
      usages: ['deriveKey'],
      extractable: false,
    }
    expect(isCryptoKey(key)).to.equal(true)
  })

  describe('isValidCryptoKey', () => {
    it('Suite with KDF is valid for both the derivable key and the derived key', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      const keyKdf: any = {
        type: 'secret',
        algorithm: { name: suite.kdf },
        usages: ['deriveKey'],
        extractable: false,
      }
      const deriveKey: any = {
        type: 'secret',
        algorithm: { name: suite.encryption, length: suite.keyLength },
        usages: ['encrypt'],
        extractable: false,
      }
      expect(isValidCryptoKey(keyKdf, material)).to.equal(true)
      expect(isValidCryptoKey(deriveKey, material)).to.equal(true)
    })

    it('Suite without the KDF is only derivable with the key', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      const keyKdf: any = {
        type: 'secret',
        algorithm: { name: 'HKDF' },
        usages: ['deriveKey'],
        extractable: false,
      }
      const key: any = {
        type: 'secret',
        algorithm: { name: suite.encryption, length: suite.keyLength },
        usages: ['encrypt'],
        extractable: false,
      }
      expect(isValidCryptoKey(keyKdf, material)).to.equal(false)
      expect(isValidCryptoKey(key, material)).to.equal(true)
    })
    it('only type === secret is valid', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      const key: any = {
        type: 'private',
        algorithm: { name: suite.encryption, length: suite.keyLength },
        usages: ['encrypt'],
        extractable: false,
      }
      expect(isValidCryptoKey(key, material)).to.equal(false)
    })

    it('length must match', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      const key: any = {
        type: 'secret',
        algorithm: { name: suite.encryption, length: suite.keyLength - 1 },
        usages: ['encrypt'],
        extractable: false,
      }
      expect(isValidCryptoKey(key, material)).to.equal(false)
    })

    it('can not be extractable', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      const key: any = {
        type: 'secret',
        algorithm: { name: suite.encryption, length: suite.keyLength },
        usages: ['encrypt'],
        extractable: true,
      }
      expect(isValidCryptoKey(key, material)).to.equal(false)
    })

    it('usage must match', () => {
      const suite = new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )
      const material = new WebCryptoEncryptionMaterial(suite, {})
      const key: any = {
        type: 'secret',
        algorithm: { name: suite.encryption, length: suite.keyLength },
        usages: ['decrypt'],
        extractable: false,
      }
      expect(isValidCryptoKey(key, material)).to.equal(false)
    })
  })
})

describe('NodeEncryptionMaterial', () => {
  const suite = new NodeAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
  )
  const test: any = new NodeEncryptionMaterial(suite, {})
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () =>
    expect(Object.isFrozen(NodeAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () =>
    expect(Object.isFrozen(NodeAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: NodeEncryptionMaterial suite must be NodeAlgorithmSuite.', () => {
    const suite: any = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => new NodeEncryptionMaterial(suite, {})).to.throw()
  })
  it('Precondition: NodeEncryptionMaterial encryptionContext must be an object, even if it is empty.', () => {
    expect(() => new NodeEncryptionMaterial(suite, undefined as any)).to.throw()
    expect(() => new NodeEncryptionMaterial(suite, true as any)).to.throw()
  })
})

describe('NodeDecryptionMaterial', () => {
  const suite = new NodeAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
  )
  const test: any = new NodeDecryptionMaterial(suite, {})
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () =>
    expect(Object.isFrozen(NodeAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () =>
    expect(Object.isFrozen(NodeAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: NodeDecryptionMaterial suite must be NodeAlgorithmSuite.', () => {
    const suite: any = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => new NodeDecryptionMaterial(suite, {})).to.throw()
  })
  it('Precondition: NodeDecryptionMaterial encryptionContext must be an object, even if it is empty.', () => {
    expect(() => new NodeDecryptionMaterial(suite, undefined as any)).to.throw()
    expect(() => new NodeDecryptionMaterial(suite, true as any)).to.throw()
  })
})

describe('WebCryptoEncryptionMaterial', () => {
  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
  )
  const test: any = new WebCryptoEncryptionMaterial(suite, {})
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () =>
    expect(Object.isFrozen(WebCryptoAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () =>
    expect(Object.isFrozen(WebCryptoAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: WebCryptoEncryptionMaterial suite must be WebCryptoAlgorithmSuite.', () => {
    const suite: any = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => new WebCryptoEncryptionMaterial(suite, {})).to.throw()
  })
  it('Precondition: WebCryptoEncryptionMaterial encryptionContext must be an object, even if it is empty.', () => {
    expect(
      () => new WebCryptoEncryptionMaterial(suite, undefined as any)
    ).to.throw()
    expect(() => new WebCryptoEncryptionMaterial(suite, true as any)).to.throw()
  })
})

describe('WebCryptoDecryptionMaterial', () => {
  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
  )
  const test: any = new WebCryptoDecryptionMaterial(suite, {})
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () =>
    expect(Object.isFrozen(WebCryptoAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () =>
    expect(Object.isFrozen(WebCryptoAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: WebCryptoDecryptionMaterial suite must be WebCryptoAlgorithmSuite.', () => {
    const suite: any = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => new WebCryptoDecryptionMaterial(suite, {})).to.throw()
  })
  it('Precondition: WebCryptoDecryptionMaterial encryptionContext must be an object, even if it is empty.', () => {
    expect(
      () => new WebCryptoDecryptionMaterial(suite, undefined as any)
    ).to.throw()
    expect(() => new WebCryptoDecryptionMaterial(suite, true as any)).to.throw()
  })
})

describe('KeyObject support', () => {
  it('supportsKeyObject tracks values of crypto module', () => {
    // supportsKeyObject should track the createSecretKey value...
    expect(!!supportsKeyObject === !!createSecretKey).to.equal(true)
  })

  if (supportsKeyObject) {
    const { KeyObject, createSecretKey } = supportsKeyObject
    describe('wrapWithKeyObjectIfSupported', () => {
      it('Uint8Array are wrapped in a KeyObject if supported', () => {
        const test = wrapWithKeyObjectIfSupported(new Uint8Array(16))
        expect(test).to.be.instanceOf(KeyObject)
      })

      it('KeyObject are return unchanged', () => {
        const dataKey = createSecretKey(new Uint8Array(16))
        expect(dataKey === wrapWithKeyObjectIfSupported(dataKey)).to.equal(true)
      })

      it('throws for unsupported types', () => {
        expect(() => wrapWithKeyObjectIfSupported({} as any)).to.throw(
          'Unsupported dataKey type'
        )
      })

      it('Postcondition: Zero the secret.  It is now inside the KeyObject.', () => {
        const dataKey = new Uint8Array(16).fill(1)
        wrapWithKeyObjectIfSupported(dataKey)
        expect(dataKey).to.deep.equal(new Uint8Array(16).fill(0))
      })
    })

    describe('unwrapDataKey', () => {
      it('returns Uint8Array unmodified', () => {
        const dataKey = new Uint8Array(16).fill(1)
        const test = unwrapDataKey(dataKey)
        expect(test === dataKey).to.equal(true)
      })

      it('exports the secret key', () => {
        const rawKey = new Uint8Array(16).fill(1)
        const dataKey = createSecretKey(rawKey)
        const test = unwrapDataKey(dataKey)
        expect(test).to.deep.equal(rawKey)
      })

      it('throws for unsupported types', () => {
        expect(() => unwrapDataKey({} as any)).to.throw(
          'Unsupported dataKey type'
        )
      })
    })
  } else {
    describe('wrapWithKeyObjectIfSupported', () => {
      it('Uint8Array are returned unchanged', () => {
        const dataKey = new Uint8Array(16)
        const test = wrapWithKeyObjectIfSupported(dataKey)
        expect(test).to.be.instanceOf(Uint8Array)
        expect(test === dataKey).to.equal(true)
      })

      it('throws for unsupported types', () => {
        expect(() => wrapWithKeyObjectIfSupported({} as any)).to.throw(
          'Unsupported dataKey type'
        )
      })
    })

    describe('unwrapDataKey', () => {
      it('returns Uint8Array unmodified', () => {
        const dataKey = new Uint8Array(16).fill(1)
        const test = unwrapDataKey(dataKey)
        expect(test === dataKey).to.equal(true)
      })

      it('throws for unsupported types', () => {
        expect(() => unwrapDataKey({} as any)).to.throw(
          'Unsupported dataKey type'
        )
      })
    })
  }
})
