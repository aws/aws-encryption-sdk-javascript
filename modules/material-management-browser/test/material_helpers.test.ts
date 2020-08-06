// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  _importCryptoKey,
  importCryptoKey,
  WebCryptoKdf,
  getSubtleFunction,
  getEncryptHelper,
  getDecryptionHelper,
} from '../src/index'
import {
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  isValidCryptoKey,
  SignatureKey,
  VerificationKey,
  AwsEsdkJsCryptoKeyPair,
  AwsEsdkJsKeyUsage,
} from '@aws-crypto/material-management'
import {
  synchronousRandomValues,
  getWebCryptoBackend,
  getZeroByteSubtle,
  getNonZeroByteBackend,
} from '@aws-crypto/web-crypto-backend'

chai.use(chaiAsPromised)
const { expect } = chai

declare const CryptoKey: CryptoKey

describe('_importCryptoKey', () => {
  it('can import WebCryptoEncryptionMaterial with a algorithm suite without a KDF', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['encrypt'])

    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })

  it('can import WebCryptoEncryptionMaterial with a algorithm suite with a KDF', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })

  it('can import WebCryptoDecryptionMaterial with a algorithm suite without a KDF', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['decrypt'])
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })

  it('can import WebCryptoDecryptionMaterial with a algorithm suite with a KDF', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })
})

describe('importCryptoKey', () => {
  it('can import when backend is isFullSupportWebCryptoBackend', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()

    const cryptoKey = await importCryptoKey(backend, material, ['encrypt'])
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })

  it('can import when backend is mixed support', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const realBackend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(realBackend)
    /* Insuring that the backend support is mixed is complicated.
     * So I just make a mixed backend and pass that.
     */
    const mixedSupportBackend = {
      nonZeroByteSubtle: subtle,
      zeroByteSubtle: subtle,
    } as any

    const mixedBackendCryptoKey = await importCryptoKey(
      mixedSupportBackend,
      material,
      ['encrypt']
    )
    expect(mixedBackendCryptoKey).to.not.be.instanceOf(CryptoKey)
    const {
      nonZeroByteCryptoKey,
      zeroByteCryptoKey,
    } = mixedBackendCryptoKey as any
    expect(nonZeroByteCryptoKey).to.be.instanceOf(CryptoKey)
    expect(zeroByteCryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(nonZeroByteCryptoKey, material)).to.equal(true)
    expect(isValidCryptoKey(zeroByteCryptoKey, material)).to.equal(true)
  })
})

describe('WebCryptoKdf', () => {
  it('returns a valid kdf key', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    const kdfKey = await WebCryptoKdf(
      subtle,
      material,
      cryptoKey,
      ['encrypt'],
      new Uint8Array(5)
    )
    expect(kdfKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(kdfKey, material)).to.equal(true)
    // for kdf...
    expect(kdfKey !== cryptoKey).to.equal(true)
  })

  it('Check for early return (Postcondition): No WebCrypto KDF, just return the unencrypted data key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['encrypt'])
    const kdfKey = await WebCryptoKdf(
      subtle,
      material,
      cryptoKey,
      ['encrypt'],
      new Uint8Array(5)
    )
    expect(kdfKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(kdfKey, material)).to.equal(true)
    // for non-kdf...
    expect(kdfKey === cryptoKey).to.equal(true)
  })

  it('Precondition: Valid HKDF values must exist for browsers.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    await expect(
      WebCryptoKdf(subtle, material, cryptoKey, ['encrypt'], new Uint8Array(0))
    ).to.rejectedWith(Error)
  })

  it('Postcondition: The derived key must conform to the algorith suite specification.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const subtleHack = {
      deriveKey() {
        return {} as any
      },
    } as any

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    await expect(
      WebCryptoKdf(
        subtleHack,
        material,
        cryptoKey,
        ['encrypt'],
        new Uint8Array(5)
      )
    ).to.rejectedWith(Error)
  })
})

describe('getSubtleFunction', () => {
  it('can get encrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()

    const cryptoKey = await importCryptoKey(backend, material, ['encrypt'])
    material.setCryptoKey(cryptoKey)

    const testInfo = getSubtleFunction(material, backend, 'encrypt')
    expect(testInfo).to.be.a('function')
    const testIvAad = testInfo(new Uint8Array(1))
    expect(testIvAad).to.be.a('function')
    const iv = new Uint8Array(suite.ivLength)
    const aad = new Uint8Array(1)
    const testFunction = testIvAad(iv, aad)
    expect(testFunction).to.be.a('function')
    const test = await testFunction(new Uint8Array(5))
    expect(test).to.be.instanceOf(ArrayBuffer)
  })

  it('Precondition: The material must have a CryptoKey.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()

    expect(() => getSubtleFunction(material, backend, 'encrypt')).to.throw()
  })

  it('Precondition: The cryptoKey and backend must match in terms of Mixed vs Full support.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    /* Insuring that the backend support is mixed is complicated.
     * So I just make a mixed backend and pass that.
     */
    const mixedSupportBackend = {
      nonZeroByteSubtle: subtle,
      zeroByteSubtle: subtle,
    } as any

    /* I always want the cryptoKey to not match the backend. */
    const cryptoKey = await _importCryptoKey(subtle, material, ['encrypt'])
    material.setCryptoKey(cryptoKey)

    expect(() =>
      getSubtleFunction(mixedSupportBackend, backend, 'encrypt')
    ).to.throw()
  })

  it('Precondition: The length of the IV must match the WebCryptoAlgorithmSuite specification.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)
    const backend = await getWebCryptoBackend()

    const cryptoKey = await importCryptoKey(backend, material, ['encrypt'])
    material.setCryptoKey(cryptoKey)

    const testInfo = getSubtleFunction(material, backend, 'encrypt')
    expect(testInfo).to.be.a('function')
    const testIvAad = testInfo(new Uint8Array(1))
    expect(testIvAad).to.be.a('function')
    const iv = new Uint8Array(suite.ivLength - 1)
    const aad = new Uint8Array(1)
    expect(() => testIvAad(iv, aad)).to.throw()
  })

  it('can encrypt/decrypt 0 bytes', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)

    const backend = await getWebCryptoBackend()
    /* All of this _only_ matters in the case of a mixed backend.
     * So I force the issue.
     */
    const mixedBackend = {
      nonZeroByteSubtle: getZeroByteSubtle(backend),
      zeroByteSubtle: getNonZeroByteBackend(backend),
      randomValues: backend.randomValues,
    }

    const cryptoKey = await importCryptoKey(mixedBackend, material, [
      'encrypt',
      'decrypt',
    ])
    material.setCryptoKey(cryptoKey)

    const iv = new Uint8Array(suite.ivLength)
    const aad = new Uint8Array(1)
    const tagLengthBytes = suite.tagLength / 8

    // Encrypt
    const testEncryptInfo = getSubtleFunction(material, mixedBackend, 'encrypt')
    const testEncryptIvAad = testEncryptInfo(new Uint8Array(1))
    const testEncryptFunction = testEncryptIvAad(iv, aad)
    const testEncryptedData = await testEncryptFunction(new Uint8Array(0))
    // Because I encrypted 0 bytes, the data should _only_ be tagLength
    expect(testEncryptedData.byteLength).to.equal(tagLengthBytes)

    // Decrypt
    const testDecryptInfo = getSubtleFunction(material, mixedBackend, 'decrypt')
    const testDecryptIvAad = testDecryptInfo(new Uint8Array(1))
    const testDecryptFunction = testDecryptIvAad(iv, aad)
    const testDecryptedData = await testDecryptFunction(
      new Uint8Array(testEncryptedData)
    )

    // Because I encrypted 0 bytes, the data should be 0 length
    expect(testDecryptedData.byteLength).to.equal(0)
  })

  it('Precondition: The WebCrypto AES-GCM decrypt API expects the data *and* tag together.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    material.setUnencryptedDataKey(udk)

    const backend = await getWebCryptoBackend()
    /* All of this _only_ matters in the case of a mixed backend.
     * So I force the issue.
     */
    const mixedBackend = {
      nonZeroByteSubtle: getZeroByteSubtle(backend),
      zeroByteSubtle: getNonZeroByteBackend(backend),
      randomValues: backend.randomValues,
    }

    const cryptoKey = await importCryptoKey(mixedBackend, material, [
      'encrypt',
      'decrypt',
    ])
    material.setCryptoKey(cryptoKey)

    const iv = new Uint8Array(suite.ivLength)
    const aad = new Uint8Array(1)
    const tagLengthBytes = suite.tagLength / 8

    // Encrypt
    const testEncryptInfo = getSubtleFunction(material, mixedBackend, 'encrypt')
    const testEncryptIvAad = testEncryptInfo(new Uint8Array(1))
    const testEncryptFunction = testEncryptIvAad(iv, aad)
    const testEncryptedData = await testEncryptFunction(new Uint8Array(0))

    // Because I encrypted 0 bytes, the data should _only_ be tagLength
    expect(testEncryptedData.byteLength).to.equal(tagLengthBytes)

    // Decrypt
    const testDecryptInfo = getSubtleFunction(material, mixedBackend, 'decrypt')
    const testDecryptIvAad = testDecryptInfo(new Uint8Array(1))
    const testDecryptFunction = testDecryptIvAad(iv, aad)

    for (let i = 0; tagLengthBytes > i; i++) {
      await expect(
        testDecryptFunction(new Uint8Array(testEncryptedData.slice(0, i)))
      ).to.eventually.rejectedWith(Error, 'Invalid data length.')
    }
  })

  it('no kdf, simple backend, can encrypt/decrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    encryptionMaterial.setUnencryptedDataKey(udk)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'encrypt',
      'decrypt',
    ])

    encryptionMaterial.setCryptoKey(cryptoKey)
    decryptionMaterial.setCryptoKey(cryptoKey)

    const info = synchronousRandomValues(5)
    const iv = synchronousRandomValues(suite.ivLength)
    const aad = synchronousRandomValues(5)
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const ciphertext = await getSubtleFunction(
      encryptionMaterial,
      backend,
      'encrypt'
    )(info)(
      iv,
      aad
    )(data)
    const plaintext = await getSubtleFunction(
      decryptionMaterial,
      backend,
      'decrypt'
    )(info)(
      iv,
      aad
    )(new Uint8Array(ciphertext))

    expect(new Uint8Array(plaintext)).to.deep.equal(data)
  })

  it('KDF, simple backend, can encrypt/decrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    encryptionMaterial.setUnencryptedDataKey(udk)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'deriveKey',
    ])

    encryptionMaterial.setCryptoKey(cryptoKey)
    decryptionMaterial.setCryptoKey(cryptoKey)

    const info = synchronousRandomValues(5)
    const iv = synchronousRandomValues(suite.ivLength)
    const aad = synchronousRandomValues(5)
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const ciphertext = await getSubtleFunction(
      encryptionMaterial,
      backend,
      'encrypt'
    )(info)(
      iv,
      aad
    )(data)
    const plaintext = await getSubtleFunction(
      decryptionMaterial,
      backend,
      'decrypt'
    )(info)(
      iv,
      aad
    )(new Uint8Array(ciphertext))

    expect(new Uint8Array(plaintext)).to.deep.equal(data)
  })

  it('no kdf, mixed backend, can encrypt/decrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    encryptionMaterial.setUnencryptedDataKey(udk)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    /* Insuring that the backend support is mixed is complicated.
     * So I just make a mixed backend and pass that.
     */
    const mixedSupportBackend = {
      nonZeroByteSubtle: subtle,
      zeroByteSubtle: subtle,
    } as any

    const cryptoKey = await importCryptoKey(
      mixedSupportBackend,
      encryptionMaterial,
      ['encrypt', 'decrypt']
    )

    encryptionMaterial.setCryptoKey(cryptoKey)
    decryptionMaterial.setCryptoKey(cryptoKey)

    const info = synchronousRandomValues(5)
    const iv = synchronousRandomValues(suite.ivLength)
    const aad = synchronousRandomValues(5)
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const ciphertext = await getSubtleFunction(
      encryptionMaterial,
      mixedSupportBackend,
      'encrypt'
    )(info)(
      iv,
      aad
    )(data)
    const plaintext = await getSubtleFunction(
      decryptionMaterial,
      mixedSupportBackend,
      'decrypt'
    )(info)(
      iv,
      aad
    )(new Uint8Array(ciphertext))

    expect(new Uint8Array(plaintext)).to.deep.equal(data)

    const ciphertextZeroByteData = await getSubtleFunction(
      encryptionMaterial,
      mixedSupportBackend,
      'encrypt'
    )(info)(
      iv,
      aad
    )(new Uint8Array(0))
    const plaintextZeroByteData = await getSubtleFunction(
      decryptionMaterial,
      mixedSupportBackend,
      'decrypt'
    )(info)(
      iv,
      aad
    )(new Uint8Array(ciphertextZeroByteData))

    expect(new Uint8Array(plaintextZeroByteData)).to.deep.equal(
      new Uint8Array(0)
    )
  })

  it('kdf, mixed backend, can encrypt/decrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    encryptionMaterial.setUnencryptedDataKey(udk)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    /* Insuring that the backend support is mixed is complicated.
     * So I just make a mixed backend and pass that.
     */
    const mixedSupportBackend = {
      nonZeroByteSubtle: subtle,
      zeroByteSubtle: subtle,
    } as any

    const cryptoKey = await importCryptoKey(
      mixedSupportBackend,
      encryptionMaterial,
      ['deriveKey']
    )

    encryptionMaterial.setCryptoKey(cryptoKey)
    decryptionMaterial.setCryptoKey(cryptoKey)

    const info = synchronousRandomValues(5)
    const iv = synchronousRandomValues(suite.ivLength)
    const aad = synchronousRandomValues(5)
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const ciphertext = await getSubtleFunction(
      encryptionMaterial,
      mixedSupportBackend,
      'encrypt'
    )(info)(
      iv,
      aad
    )(data)
    const plaintext = await getSubtleFunction(
      decryptionMaterial,
      mixedSupportBackend,
      'decrypt'
    )(info)(
      iv,
      aad
    )(new Uint8Array(ciphertext))

    expect(new Uint8Array(plaintext)).to.deep.equal(data)

    const ciphertextZeroByteData = await getSubtleFunction(
      encryptionMaterial,
      mixedSupportBackend,
      'encrypt'
    )(info)(
      iv,
      aad
    )(new Uint8Array(0))
    const plaintextZeroByteData = await getSubtleFunction(
      decryptionMaterial,
      mixedSupportBackend,
      'decrypt'
    )(info)(
      iv,
      aad
    )(new Uint8Array(ciphertextZeroByteData))

    expect(new Uint8Array(plaintextZeroByteData)).to.deep.equal(
      new Uint8Array(0)
    )
  })
})

// getEncryptHelper
// getDecryptionHelper

describe('getEncryptHelper/getDecryptionHelper', () => {
  it('encryption helpers without a signature', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)

    encryptionMaterial.setUnencryptedDataKey(udk)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'deriveKey',
    ])
    encryptionMaterial.setCryptoKey(cryptoKey)

    const test = await getEncryptHelper(encryptionMaterial)
    expect(test.kdfGetSubtleEncrypt).to.be.a('function')
    expect(test.subtleSign).to.equal(undefined)
    expect(test.dispose).to.be.a('function')
  })

  it('decryption helpers without a signature ', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    decryptionMaterial.setUnencryptedDataKey(udk)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, decryptionMaterial, [
      'deriveKey',
    ])
    decryptionMaterial.setCryptoKey(cryptoKey)

    const test = await getDecryptionHelper(decryptionMaterial)
    expect(test.kdfGetSubtleDecrypt).to.be.a('function')
    expect(test.subtleVerify).to.equal(undefined)
    expect(test.dispose).to.be.a('function')
  })

  it('encryption helpers with a signature', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const { signatureKey } = await sigKeys(suite)

    encryptionMaterial.setUnencryptedDataKey(udk).setSignatureKey(signatureKey)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'deriveKey',
    ])
    encryptionMaterial.setCryptoKey(cryptoKey)

    const test = await getEncryptHelper(encryptionMaterial)
    expect(test.kdfGetSubtleEncrypt).to.be.a('function')
    expect(test.subtleSign).to.be.a('function')
    expect(test.dispose).to.be.a('function')
  })

  it('decryption helpers with a signature ', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const { verificationKey } = await sigKeys(suite)

    decryptionMaterial
      .setUnencryptedDataKey(udk)
      .setVerificationKey(verificationKey)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, decryptionMaterial, [
      'deriveKey',
    ])
    decryptionMaterial.setCryptoKey(cryptoKey)

    const test = await getDecryptionHelper(decryptionMaterial)
    expect(test.kdfGetSubtleDecrypt).to.be.a('function')
    expect(test.subtleVerify).to.be.a('function')
    expect(test.dispose).to.be.a('function')
  })

  it('Precondition: WebCryptoEncryptionMaterial must have a valid data key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})

    await expect(getEncryptHelper(encryptionMaterial)).to.rejectedWith(Error)
  })

  it('Precondition: WebCryptoDecryptionMaterial must have a valid data key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})

    await expect(getDecryptionHelper(decryptionMaterial)).to.rejectedWith(Error)
  })

  it('can verify what was signed', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const { signatureKey, verificationKey } = await sigKeys(suite)

    decryptionMaterial
      .setUnencryptedDataKey(udk)
      .setVerificationKey(verificationKey)
    encryptionMaterial.setUnencryptedDataKey(udk).setSignatureKey(signatureKey)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'deriveKey',
    ])

    encryptionMaterial.setCryptoKey(cryptoKey)
    decryptionMaterial.setCryptoKey(cryptoKey)

    const { subtleSign } = await getEncryptHelper(encryptionMaterial)
    const { subtleVerify } = await getDecryptionHelper(decryptionMaterial)

    const data = new Uint8Array([1, 2, 3, 4, 5])
    // Make Typescript happy
    if (!subtleSign || !subtleVerify) throw new Error('never')

    const sig = await subtleSign(data)
    const test = await subtleVerify(new Uint8Array(sig), data)
    expect(test).to.equal(true)
  })
})

/* A simple helper to get signature/verification keys.
 * Basically a copy from the cmm.
 */
async function sigKeys(suite: WebCryptoAlgorithmSuite) {
  const { signatureCurve: namedCurve } = suite
  if (!namedCurve) throw new Error('never')
  const backend = await getWebCryptoBackend()
  const subtle = getZeroByteSubtle(backend)

  const webCryptoAlgorithm = { name: 'ECDSA', namedCurve }
  const extractable = false
  const usages = ['sign', 'verify'] as AwsEsdkJsKeyUsage[]
  const format = 'raw'

  const { publicKey, privateKey } = (await subtle.generateKey(
    webCryptoAlgorithm,
    extractable,
    usages
  )) as AwsEsdkJsCryptoKeyPair
  const publicKeyBytes = await subtle.exportKey(format, publicKey)
  const compressPoint = SignatureKey.encodeCompressPoint(
    new Uint8Array(publicKeyBytes),
    suite
  )

  const signatureKey = new SignatureKey(privateKey, compressPoint, suite)
  const verificationKey = new VerificationKey(publicKey, suite)

  return { signatureKey, verificationKey }
}
