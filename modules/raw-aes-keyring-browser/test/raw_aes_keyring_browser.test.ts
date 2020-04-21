// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  RawAesKeyringWebCrypto,
  RawAesWrappingSuiteIdentifier,
} from '../src/index'
import {
  WebCryptoEncryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  WebCryptoDecryptionMaterial,
} from '@aws-crypto/material-management-browser'

chai.use(chaiAsPromised)
const { expect } = chai

declare const CryptoKey: CryptoKey
describe('importCryptoKey', () => {
  it('returns CryptoKey', async () => {
    const suiteId =
      RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
    const udk = new Uint8Array(128 / 8)
    const cryptoKey = await RawAesKeyringWebCrypto.importCryptoKey(udk, suiteId)
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
  })

  it('Precondition: masterKey must correspond to the algorithm suite specification.', async () => {
    const suiteId =
      RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
    const notValidLength = new Uint8Array(10)

    await expect(
      RawAesKeyringWebCrypto.importCryptoKey(notValidLength, suiteId)
    ).to.rejectedWith(Error)
  })
})

describe('RawAesKeyringWebCrypto::constructor', () => {
  const wrappingSuite =
    RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const udk = new Uint8Array(128 / 8)
  const keyNamespace = 'keyNamespace'
  const keyName = 'keyName'

  it('constructor decorates', async () => {
    const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(
      udk,
      wrappingSuite
    )
    const test = new RawAesKeyringWebCrypto({
      keyName,
      keyNamespace,
      masterKey,
      wrappingSuite,
    })
    expect(test.keyName).to.equal(keyName)
    expect(test.keyNamespace).to.equal(keyNamespace)
    expect(test._wrapKey).to.be.a('function')
    expect(test._unwrapKey).to.be.a('function')
  })

  it('Precondition: AesKeyringWebCrypto needs identifying information for encrypt and decrypt.', async () => {
    const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(
      udk,
      wrappingSuite
    )
    expect(
      () =>
        new RawAesKeyringWebCrypto({
          keyNamespace,
          masterKey,
          wrappingSuite,
        } as any)
    ).to.throw()
    expect(
      () =>
        new RawAesKeyringWebCrypto({ keyName, masterKey, wrappingSuite } as any)
    ).to.throw()
  })

  it('Precondition: RawAesKeyringWebCrypto requires a wrappingSuite to be a valid RawAesWrappingSuite.', async () => {
    const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(
      udk,
      wrappingSuite
    )
    expect(
      () =>
        new RawAesKeyringWebCrypto({
          keyName,
          keyNamespace,
          masterKey,
          wrappingSuite: 111 as any,
        })
    ).to.throw()
  })

  it('Precondition: unencryptedMasterKey must correspond to the WebCryptoAlgorithmSuite specification.', async () => {
    const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(
      udk,
      wrappingSuite
    )
    expect(
      () =>
        new RawAesKeyringWebCrypto({
          keyName,
          keyNamespace,
          masterKey,
          wrappingSuite:
            RawAesWrappingSuiteIdentifier.AES192_GCM_IV12_TAG16_NO_PADDING,
        })
    ).to.throw()
  })
})

describe('RawAesKeyringWebCrypto::_filter', () => {
  const wrappingSuite =
    RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const udk = new Uint8Array(128 / 8)
  const keyNamespace = 'keyNamespace'
  const keyName = 'keyName'
  let keyring: RawAesKeyringWebCrypto
  before(async () => {
    const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(
      udk,
      wrappingSuite
    )
    keyring = new RawAesKeyringWebCrypto({
      keyName,
      keyNamespace,
      masterKey,
      wrappingSuite,
    })
  })

  it('true', async () => {
    const test = keyring._filter({
      providerId: keyNamespace,
      providerInfo: keyName,
    } as any)
    expect(test).to.equal(true)
  })

  it('true', async () => {
    const test = keyring._filter({
      providerId: keyNamespace,
      providerInfo: keyName + 'other stuff',
    } as any)
    expect(test).to.equal(true)
  })

  it('false', async () => {
    expect(
      keyring._filter({
        providerId: 'not: keyNamespace',
        providerInfo: keyName + 'other stuff',
      } as any)
    ).to.equal(false)

    expect(
      keyring._filter({
        providerId: keyNamespace,
        providerInfo: 'not: keyName',
      } as any)
    ).to.equal(false)
  })
})

describe('RawAesKeyringWebCrypto encrypt/decrypt', () => {
  const wrappingSuite =
    RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const masterUdk = new Uint8Array(128 / 8)
  const keyNamespace = 'keyNamespace'
  const keyName = 'keyName'
  let keyring: RawAesKeyringWebCrypto
  let encryptedDataKey: EncryptedDataKey
  before(async () => {
    const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(
      masterUdk,
      wrappingSuite
    )
    keyring = new RawAesKeyringWebCrypto({
      keyName,
      keyNamespace,
      masterKey,
      wrappingSuite,
    })
  })

  it('can encrypt and create unencrypted data key', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const test = await keyring.onEncrypt(material)
    expect(test.hasValidKey()).to.equal(true)
    const udk = test.getUnencryptedDataKey()
    expect(udk).to.have.lengthOf(suite.keyLengthBytes)
    expect(test.encryptedDataKeys).to.have.lengthOf(1)
    const [edk] = test.encryptedDataKeys
    expect(edk.providerId).to.equal(keyNamespace)
    encryptedDataKey = edk
  })

  it('can decrypt an EncryptedDataKey', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const test = await keyring.onDecrypt(material, [encryptedDataKey])
    expect(test.hasValidKey()).to.equal(true)
    // The UnencryptedDataKey should be zeroed, because the cryptoKey has been set
    expect(() => test.getUnencryptedDataKey()).to.throw()
  })
})
