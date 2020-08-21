// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  _importCryptoKey,
  importCryptoKey,
  WebCryptoKdf,
  currySubtleFunction,
  deriveKeyCommitment,
  importForWebCryptoEncryptionMaterial,
  GetEncryptInfo,
  importForWebCryptoDecryptionMaterial,
  GetDecryptInfo,
} from '../src/index'
import {
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  isValidCryptoKey,
  needs,
} from '@aws-crypto/material-management'
import {
  synchronousRandomValues,
  getWebCryptoBackend,
  getZeroByteSubtle,
} from '@aws-crypto/web-crypto-backend'
import { MessageIdLength } from '@aws-crypto/serialize'

chai.use(chaiAsPromised)
const { expect } = chai

declare const CryptoKey: CryptoKey

describe('commitKey crypto', () => {
  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
  )

  // prettier-ignore
  const messageId = new Uint8Array([
    77, 251, 209, 49,  77, 157,  85, 146,
    91, 129, 114, 50, 197, 227, 109, 110,
    62,  94,  35, 15,   1, 137,  48, 226,
   194, 193, 242, 67, 246, 125, 193, 121
 ])
  // prettier-ignore
  const dataKey = new Uint8Array([
    250, 158, 190, 194,  19, 213, 195,
    217,  14, 173, 130, 217,  20, 196,
     65,  39, 105, 250,  86,  88, 186,
     79, 254, 211, 146,  48, 232, 185,
     47, 182, 230, 205
  ])
  // prettier-ignore
  const commitKey = new Uint8Array([
    23, 207,   8, 247, 51, 219,  81,   4,
   159,  58,  92, 203, 94, 255, 174,  33,
   141, 190, 155, 241, 58, 143,  99, 204,
   177, 184,  30,  29, 81, 255,  47,  76
 ])
  // The key is not exportable.
  // So I can not verify
  // that the derived key matches.
  // To test this see `can decrypt what was encrypted`
  // this approaches this by decrypting what was encrypted.

  const material = new WebCryptoDecryptionMaterial(
    suite,
    {}
  ).setUnencryptedDataKey(dataKey, {
    keyNamespace: 'k',
    keyName: 'k',
    flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
  })

  let cryptoKey: CryptoKey
  let subtle: SubtleCrypto

  before(async () => {
    const backend = await getWebCryptoBackend()
    subtle = getZeroByteSubtle(backend)
    cryptoKey = await _importCryptoKey(subtle, material)
  })

  describe('WebCryptoKdf', () => {
    it('can derive a committed algorithm', async () => {
      needs(isValidCryptoKey(cryptoKey, material), 'bad')
      // Not sure how to test the key, it is pretty opaque.
      await WebCryptoKdf(
        subtle,
        material,
        cryptoKey,
        ['decrypt'],
        messageId,
        commitKey
      )
    })
  })

  describe('deriveKeyCommitment', () => {
    it('can derive commit key', async () => {
      needs(isValidCryptoKey(cryptoKey, material), 'bad')
      /* If these values are not equal,
       * it will throw.
       */
      await deriveKeyCommitment(
        subtle,
        material,
        cryptoKey,
        messageId,
        commitKey
      )
    })
  })
})

describe('currySubtleFunction', () => {
  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
  )
  const dataKey = synchronousRandomValues(suite.keyLengthBytes)
  const nonce = synchronousRandomValues(MessageIdLength.V2)
  const iv = new Uint8Array(12)
  // 'plaintext' as utf-8
  const plaintext = new Uint8Array([112, 108, 97, 105, 110, 116, 101, 120, 116])

  // The authTag is concatenated with the ciphertext...
  let ciphertext: ArrayBuffer
  let commitKey: Uint8Array | undefined

  it('can encrypt', async () => {
    const material = await importForWebCryptoEncryptionMaterial(
      new WebCryptoEncryptionMaterial(suite, {}).setUnencryptedDataKey(
        dataKey,
        {
          keyName: 'keyName',
          keyNamespace: 'keyNamespace',
          flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
        }
      )
    )
    const backend = await getWebCryptoBackend()

    const encryptInfo = currySubtleFunction(
      material,
      backend,
      'encrypt'
    ) as GetEncryptInfo
    const { getSubtleEncrypt, keyCommitment } = await encryptInfo(nonce)
    commitKey = keyCommitment
    ciphertext = await getSubtleEncrypt(iv, new Uint8Array(0))(plaintext)
  })

  it('can decrypt what was encrypted', async () => {
    const material = await importForWebCryptoDecryptionMaterial(
      new WebCryptoDecryptionMaterial(suite, {}).setUnencryptedDataKey(
        dataKey,
        {
          keyName: 'keyName',
          keyNamespace: 'keyNamespace',
          flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
        }
      )
    )
    const backend = await getWebCryptoBackend()

    const decryptInfo = currySubtleFunction(
      material,
      backend,
      'decrypt'
    ) as GetDecryptInfo
    const getSubtleDecrypt = await decryptInfo(nonce, commitKey)

    const test = await getSubtleDecrypt(
      iv,
      new Uint8Array(0)
    )(new Uint8Array(ciphertext))
    expect(new Uint8Array(test)).to.deep.equal(plaintext)
  })

  it('can get encrypt legacy', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()

    const cryptoKey = await importCryptoKey(backend, material, ['encrypt'])
    material.setCryptoKey(cryptoKey, trace)

    const testInfo = currySubtleFunction(material, backend, 'encrypt')
    expect(testInfo).to.be.a('function')
    const { getSubtleEncrypt: testIvAad } = await testInfo(
      new Uint8Array(MessageIdLength.V1)
    )
    expect(testIvAad).to.be.a('function')
    const iv = new Uint8Array(suite.ivLength)
    const aad = new Uint8Array(1)
    const testFunction = testIvAad(iv, aad)
    expect(testFunction).to.be.a('function')
    const test = await testFunction(new Uint8Array(16))
    expect(test).to.be.instanceOf(ArrayBuffer)
  })
})
