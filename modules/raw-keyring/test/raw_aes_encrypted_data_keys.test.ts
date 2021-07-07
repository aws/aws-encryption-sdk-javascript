// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  rawAesEncryptedDataKeyFactory,
  rawAesEncryptedPartsFactory,
} from '../src/raw_aes_encrypted_data_keys'
import {
  EncryptedDataKey,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
} from '@aws-crypto/material-management'

const keyNamespace = 'keyNamespace'
const keyName = 'keyName'
const keyNameFromUtf8 = new Uint8Array([107, 101, 121, 78, 97, 109, 101])
const iv = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
const ciphertext = new Uint8Array([
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
])
const authTag = new Uint8Array([3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3])

const compoundString =
  keyName +
  '\u0000\u0000\u0000�\u0000\u0000\u0000\f\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001'
const compoundUint8Array = new Uint8Array([
  ...keyNameFromUtf8, // keyName as UTF-8
  0,
  0,
  0,
  16 * 8, // uInt32BE(authTagBitLength)
  0,
  0,
  0,
  12, // uInt32BE(ivLength)
  ...iv,
])
const encryptedDataKey = new Uint8Array([...ciphertext, ...authTag])
const suite = new NodeAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
)

describe('rawAesEncryptedDataKeyFactory:rawAesEncryptedDataKey', () => {
  it('will build an EncryptedDataKey', () => {
    let fromUtf8Called = 0
    const fromUtf8 = (str: string) => {
      expect(str).to.equal(keyName)
      fromUtf8Called += 1
      return new Uint8Array([107, 101, 121, 78, 97, 109, 101])
    }

    let toUtf8Called = 0
    const toUtf8 = (bytes: Uint8Array) => {
      expect(bytes).to.deep.equal(compoundUint8Array)

      toUtf8Called += 1
      return compoundString
    }

    const { rawAesEncryptedDataKey } = rawAesEncryptedDataKeyFactory(
      toUtf8,
      fromUtf8
    )

    const test = rawAesEncryptedDataKey(
      keyNamespace,
      keyName,
      iv,
      ciphertext,
      authTag
    )

    expect(test).to.be.instanceOf(EncryptedDataKey)
    expect(test.encryptedDataKey).to.deep.equal(encryptedDataKey)
    expect(test.providerId).to.equal(keyNamespace)
    expect(test.providerInfo).to.equal(compoundString)
    expect(test.rawInfo).to.deep.equal(compoundUint8Array)
    expect(toUtf8Called).to.equal(1)
    expect(fromUtf8Called).to.equal(1)
  })
})

describe('rawAesEncryptedPartsFactory:rawAesEncryptedParts', () => {
  it('returns correct authTag, ciphertext, iv', () => {
    const edk = new EncryptedDataKey({
      encryptedDataKey,
      providerId: keyNamespace,
      providerInfo: compoundString,
      rawInfo: compoundUint8Array,
    })

    let fromUtf8Called = 0
    const fromUtf8 = (str: string) => {
      expect(str).to.equal(keyName)
      fromUtf8Called += 1
      return keyNameFromUtf8
    }

    const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)
    const test = rawAesEncryptedParts(suite, keyName, edk)

    expect(test.authTag).to.deep.equal(authTag)
    expect(test.ciphertext).to.deep.equal(ciphertext)
    expect(test.iv).to.deep.equal(iv)
    expect(fromUtf8Called).to.equal(1)
  })

  it('Precondition: rawInfo must be a Uint8Array.', () => {
    const edk = {
      encryptedDataKey,
      providerId: keyNamespace,
      providerInfo: compoundString,
      rawInfo: '',
    } as any

    const fromUtf8Called = 0
    const fromUtf8 = () => {
      throw new Error('never')
    }

    const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)

    expect(() => rawAesEncryptedParts(suite, keyName, edk)).to.throw()
    expect(fromUtf8Called).to.equal(0)
  })

  it('Precondition: The ivLength must match the algorith suite specification.', () => {
    const compoundUint8Array = new Uint8Array([
      ...keyNameFromUtf8, // keyName as UTF-8
      0,
      0,
      0,
      16 * 8, // uInt32BE(authTagBitLength)
      0,
      0,
      0,
      13, // wrong length
      ...iv,
    ])

    const edk = new EncryptedDataKey({
      encryptedDataKey,
      providerId: keyNamespace,
      providerInfo: compoundString,
      rawInfo: compoundUint8Array,
    })

    const fromUtf8 = () => keyNameFromUtf8

    const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)
    expect(() => rawAesEncryptedParts(suite, keyName, edk)).to.throw()
  })

  it('Precondition: The tagLength must match the algorith suite specification.', () => {
    const compoundUint8Array = new Uint8Array([
      ...keyNameFromUtf8, // keyName as UTF-8
      0,
      0,
      0,
      17 * 8, // wrong length
      0,
      0,
      0,
      12, // right length
      ...iv,
    ])

    const edk = new EncryptedDataKey({
      encryptedDataKey,
      providerId: keyNamespace,
      providerInfo: compoundString,
      rawInfo: compoundUint8Array,
    })

    const fromUtf8 = () => keyNameFromUtf8

    const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)
    expect(() => rawAesEncryptedParts(suite, keyName, edk)).to.throw()
  })

  it('Precondition: The byteLength of rawInfo should match the encoded length.', () => {
    const makeEdk = (rawInfo: Uint8Array) =>
      new EncryptedDataKey({
        encryptedDataKey,
        providerId: keyNamespace,
        providerInfo: compoundString,
        rawInfo,
      })

    const fromUtf8 = () => keyNameFromUtf8

    const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)

    const tooShort = new Uint8Array([1, 1, 1])
    const tooLong = new Uint8Array([
      ...keyNameFromUtf8, // keyName as UTF-8
      0,
      0,
      0,
      16 * 8, // wrong length
      0,
      0,
      0,
      12, // right length
      ...iv,
      0,
    ])

    expect(() =>
      rawAesEncryptedParts(suite, keyName, makeEdk(tooShort))
    ).to.throw()
    expect(() =>
      rawAesEncryptedParts(suite, keyName, makeEdk(tooLong))
    ).to.throw()
  })

  it('Precondition: The encryptedDataKey byteLength must match the algorith suite specification and encoded length.', () => {
    const compoundUint8Array = new Uint8Array([
      ...keyNameFromUtf8, // keyName as UTF-8
      0,
      0,
      0,
      17 * 8, // wrong length
      0,
      0,
      0,
      12, // right length
      ...iv,
    ])

    const edk = new EncryptedDataKey({
      encryptedDataKey: new Uint8Array([...encryptedDataKey, 0]),
      providerId: keyNamespace,
      providerInfo: compoundString,
      rawInfo: compoundUint8Array,
    })

    const fromUtf8 = () => keyNameFromUtf8

    const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)
    expect(() => rawAesEncryptedParts(suite, keyName, edk)).to.throw()
  })
})
