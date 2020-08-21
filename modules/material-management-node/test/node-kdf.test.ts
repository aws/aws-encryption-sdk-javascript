// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  NodeDecryptionMaterial,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  unwrapDataKey,
  NodeEncryptionMaterial,
  needs,
} from '@aws-crypto/material-management'
import { nodeKdf, curryCryptoStream } from '../src/material_helpers'
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto'
import { MessageIdLength } from '@aws-crypto/serialize'

describe('nodeKdf v2 commitment', () => {
  it('basic test vectors', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
    )

    const messageIdBase64 = 'TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXk='
    const dataKeyBase64 = '+p6+whPVw9kOrYLZFMRBJ2n6Vli6T/7TkjDouS+25s0='
    const commitKeyBase64 = 'F88I9zPbUQSfOlzLXv+uIY2+m/E6j2PMsbgeHVH/L0w='
    const expectedKeyBase64 = 'V67301yMJtk0jxOc3QJeBac6uKxO3XylWtkKTYmUU+M='

    const messageId = Buffer.alloc(32, messageIdBase64, 'base64')
    const dataKey = Buffer.alloc(32, dataKeyBase64, 'base64')
    const commitKey = Buffer.alloc(32, commitKeyBase64, 'base64')
    const expectedKey = Buffer.alloc(32, expectedKeyBase64, 'base64')

    const material = new NodeDecryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(dataKey, {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    })

    const test = unwrapDataKey(
      nodeKdf(material, messageId, commitKey).derivedKey
    )
    expect(test).to.not.deep.equal(dataKey)
    expect(test.byteLength).to.equal(suite.keyLengthBytes)
    expect(test).to.deep.equal(expectedKey)
  })
})

describe('curryCryptoStream: Committed Algorithm suite', () => {
  const suite = new NodeAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
  )
  const dataKey = randomBytes(suite.keyLengthBytes)
  const nonce = randomBytes(MessageIdLength.V2)
  const iv = new Uint8Array(12)
  const plaintext = Buffer.from('plaintext')

  let ciphertext: Buffer
  let commitKey: Uint8Array | undefined
  let authTag: Buffer

  it('can encrypt', () => {
    const material = new NodeEncryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(dataKey), {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
    const { getCipher, keyCommitment } = curryCryptoStream(
      material,
      createCipheriv
    )(nonce)
    commitKey = keyCommitment

    const cipher = getCipher(iv)
    ciphertext = cipher.update(plaintext)
    expect(cipher.final()).lengthOf(0)
    authTag = cipher.getAuthTag()
  })

  it('can decrypt what was encrypted', () => {
    const material = new NodeDecryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(dataKey), {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    })

    const createCryptoStream = curryCryptoStream(material, createDecipheriv)(
      nonce,
      commitKey
    )
    needs(
      !('createCryptoStream' in createCryptoStream),
      'curryCryptoStream unexpected return'
    )
    const decipher = createCryptoStream(iv)
    decipher.setAuthTag(authTag)
    const test = decipher.update(ciphertext)
    expect(decipher.final()).lengthOf(0)
    expect(test).to.deep.equal(plaintext)
  })
})
