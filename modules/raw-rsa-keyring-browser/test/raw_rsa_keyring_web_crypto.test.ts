// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { RsaImportableKey, RawRsaKeyringWebCrypto } from '../src/index'
import {
  KeyringWebCrypto,
  WebCryptoEncryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  WebCryptoDecryptionMaterial,
} from '@aws-crypto/material-management-browser'

chai.use(chaiAsPromised)
const { expect } = chai

declare const CryptoKey: CryptoKey

/* JWK for the RSA Keys to use.
 * These keys are *Public*!
 * *DO NOT USE*
 */
const privateRsaJwkKey: RsaImportableKey = {
  alg: 'RSA-OAEP-256',
  d: 'XcAlS3OYtZ5F3BFGRQH5B8soiqstUk9JkH6_sUhBUfM7yjFpn3MQACtGgOKsFIO01KWCVl7Cn6E3c-MuuT3QqNQrUx8n-WrJU8qNpDOGJ5CVpG9-xTSQVNzRV92gj8g7-BIgehtzMmirXXNsb1XeTg9zsm3iptt9VyhplGqcgOdmm72sT1Z8ZmkagaElHSg0dR1ZNGgzSfTtRg_J1tTh7cmFb1LVz069o6cRaa5ueOPNKxmEslBdVWsDo9naxd_keLiqOOMIQp-KlLuQ-Zhn5fZyqxkRPGjTKZZHitgurzfWG4ERjjrYCbZsOjEt9Tj8FXXUB8bd3qRPy5UkN-XLEQ',
  dp: 'V8QYdWm4OqWpfF_NPdCGr5eqztfHiQQn1NLmkvNO8c9dc2yNizZ4GxtNNEARYjgnLK0ROCoiK5yamtVDyjZ_zzZUvE0CG8iNRg1qvaOM8n_7B2YgmUs9rJ-QKK3HVEsi_M0x-hHeRl3ocAkNfby3__yt6s43FvyrccQh89WcAr0',
  dq: 'NT5lrYlvkOwXIHl8P9AQm1nNL0RkHSrWahYlagRkyU3ELySlWr2laDxXzPnngpuBvyA98iq6Z2JTn8ArtXXvTqQk6BF6np6qqg1QNQxsQeU4Aj3xOMV9EGh57Zpa8Rs0jVydxBdlRW03Fr0UChHKxmT2kS0622gdlGQAs3YxMck',
  e: 'AQAB',
  ext: true,
  key_ops: ['unwrapKey'],
  kty: 'RSA',
  n: '6k_jrxg7mpz7CzgAr6eRqJr1VlvjJ9uQY71hadkDZkLLZHiMl7hz73lqq3w2MfHCa3Pf3BVo5TCXGYuxKOlPb7bH0WWpMeAzOKR_X27UqfA8MBVGb4YO5HXqw0jup8-I-Zi3CQAmP87uE6GDuh7xzeAcwpGD5xE0N74-uWq3YS92PFHCavtryx-ad9VGTgfAbkV3k1-RSxIiZjzbAt3exBAn5EjMfF6FMI70_HYqO-5xGv_aAPSa1OMc_buK5QACN7gmFwqHBzw98v93iyGUc4_XJNL-jPzKNP4AT1zMc6p6RxF3SYytNq7iXIjUmm-oY8fvCSmT1F13XKdzv7DLOw',
  p: '9dGuBwEDeOHFwJ_AQXHBWu53bv_L1_9lh2X-NEBO1B7YMhYWu2nMqXEvLpwvPqyBXwWnuPdfGqu6BHv22RDAF7Lu_oUshq-9dzSwFxaC5PQ2NwtHnz0-zwhEzCE3Qw9t63_OXX87gjp5vy6c5bvb3B9EbZU33Xf9nqVEJhzFreU',
  q: '9AQ0oYhctBbFuIu4jt1HBmqQGGAECbhQAMw324MX8pVUg6GOtF0X822iEsq7aIfY8u5nTWu1kKl6s84US1yII0sJmW2Jj722r5VYDIrxk5x_mLQ6jXmfuH2kl-Lvzo6aHIVkDLIK-IaPt5teSwG71QfAPDgR6drIAuSFnJZ2Ap8',
  qi: 'mfoT9tmXPhLBanX5Mg76pO21NAXR1aAQ76tS1_hJZYxP8iZtmlEdvvAMIdSibvIt7Gfi60rBPnxqmmKuitJfzIVCd4sVLjIVEjT_njjLAzU-NTQdGugPCWWo8jB8NyeFy6nrZa_Hy52ijBn-Xt5G8pzvz5lF5gRfCe09y14oNeQ',
}
const publicRsaJwkKey: RsaImportableKey = {
  alg: 'RSA-OAEP-256',
  e: 'AQAB',
  ext: true,
  key_ops: ['wrapKey'],
  kty: 'RSA',
  n: '6k_jrxg7mpz7CzgAr6eRqJr1VlvjJ9uQY71hadkDZkLLZHiMl7hz73lqq3w2MfHCa3Pf3BVo5TCXGYuxKOlPb7bH0WWpMeAzOKR_X27UqfA8MBVGb4YO5HXqw0jup8-I-Zi3CQAmP87uE6GDuh7xzeAcwpGD5xE0N74-uWq3YS92PFHCavtryx-ad9VGTgfAbkV3k1-RSxIiZjzbAt3exBAn5EjMfF6FMI70_HYqO-5xGv_aAPSa1OMc_buK5QACN7gmFwqHBzw98v93iyGUc4_XJNL-jPzKNP4AT1zMc6p6RxF3SYytNq7iXIjUmm-oY8fvCSmT1F13XKdzv7DLOw',
}

describe('import CryptoKey helpers', () => {
  it('imports public CryptoKey', async () => {
    const cryptoKey = await RawRsaKeyringWebCrypto.importPublicKey(
      publicRsaJwkKey
    )
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
  })

  it('imports private CryptoKey', async () => {
    const cryptoKey = await RawRsaKeyringWebCrypto.importPrivateKey(
      privateRsaJwkKey
    )
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
  })
})

describe('RawRsaKeyringWebCrypto::constructor', () => {
  let publicCryptoKey: CryptoKey
  let privateCryptoKey: any
  const keyName = 'keyName'
  const keyNamespace = 'keyNamespace'

  before(async () => {
    publicCryptoKey = await await RawRsaKeyringWebCrypto.importPublicKey(
      publicRsaJwkKey
    )
    privateCryptoKey = await await RawRsaKeyringWebCrypto.importPrivateKey(
      privateRsaJwkKey
    )
  })

  it('constructor decorates', async () => {
    const test = new RawRsaKeyringWebCrypto({
      privateKey: privateCryptoKey,
      publicKey: publicCryptoKey,
      keyName,
      keyNamespace,
    })

    expect(test.keyName).to.equal(keyName)
    expect(test.keyNamespace).to.equal(keyNamespace)
    expect(test._wrapKey).to.be.a('function')
    expect(test._unwrapKey).to.be.a('function')
    expect(test).to.be.instanceOf(KeyringWebCrypto)
  })

  it('can construct with only public key', () => {
    const testPublicOnly = new RawRsaKeyringWebCrypto({
      publicKey: publicCryptoKey,
      keyName,
      keyNamespace,
    })
    expect(testPublicOnly).to.be.instanceOf(RawRsaKeyringWebCrypto)
  })

  it('can construct with only private key', () => {
    const testPrivateOnly = new RawRsaKeyringWebCrypto({
      privateKey: privateCryptoKey,
      keyName,
      keyNamespace,
    })
    expect(testPrivateOnly).to.be.instanceOf(RawRsaKeyringWebCrypto)
  })

  it('Precondition: RsaKeyringWebCrypto needs either a public or a private key to operate.', () => {
    expect(
      () =>
        new RawRsaKeyringWebCrypto({
          keyName,
          keyNamespace,
        })
    ).to.throw()
  })

  it('Precondition: RsaKeyringWebCrypto needs identifying information for encrypt and decrypt.', () => {
    expect(
      () =>
        new RawRsaKeyringWebCrypto({
          privateKey: privateCryptoKey,
          publicKey: publicCryptoKey,
        } as any)
    ).to.throw()
    expect(
      () =>
        new RawRsaKeyringWebCrypto({
          privateKey: privateCryptoKey,
          publicKey: publicCryptoKey,
          keyNamespace,
        } as any)
    ).to.throw()
    expect(
      () =>
        new RawRsaKeyringWebCrypto({
          privateKey: privateCryptoKey,
          publicKey: publicCryptoKey,
          keyName,
        } as any)
    ).to.throw()
  })
})

describe('RawRsaKeyringWebCrypto encrypt/decrypt', () => {
  const keyNamespace = 'keyNamespace'
  const keyName = 'keyName'
  let keyring: RawRsaKeyringWebCrypto
  let encryptedDataKey: EncryptedDataKey

  before(async () => {
    const publicKey = await await RawRsaKeyringWebCrypto.importPublicKey(
      publicRsaJwkKey
    )
    const privateKey = await await RawRsaKeyringWebCrypto.importPrivateKey(
      privateRsaJwkKey
    )
    keyring = new RawRsaKeyringWebCrypto({
      publicKey,
      privateKey,
      keyName,
      keyNamespace,
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

  it('Precondition: I must have a publicKey to wrap.', async () => {
    const privateKey = await await RawRsaKeyringWebCrypto.importPrivateKey(
      privateRsaJwkKey
    )
    const keyring = new RawRsaKeyringWebCrypto({
      privateKey,
      keyName,
      keyNamespace,
    })

    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    await expect(keyring.onEncrypt(material)).to.rejectedWith(Error)
  })

  it('Precondition: I must have a privateKey to unwrap.', async () => {
    const publicKey = await await RawRsaKeyringWebCrypto.importPublicKey(
      publicRsaJwkKey
    )
    const keyring = new RawRsaKeyringWebCrypto({
      publicKey,
      keyName,
      keyNamespace,
    })

    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    await expect(
      keyring._unwrapKey(material, encryptedDataKey)
    ).to.rejectedWith(Error)
  })
})
