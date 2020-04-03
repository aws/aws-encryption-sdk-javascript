// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management-node'
import { decrypt } from '../src/index'
import * as fixtures from './fixtures'
import from from 'from2'

describe('decrypt', () => {
  it('string with encoding', async () => {
    const { plaintext: test, messageHeader } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(),
      { encoding: 'base64' }
    )

    expect(messageHeader.suiteId).to.equal(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
    expect(messageHeader.encryptionContext).to.deep.equal(fixtures.encryptionContext())
    expect(test.toString('base64')).to.equal(fixtures.base64Plaintext())
  })

  it('buffer', async () => {
    const { plaintext: test, messageHeader } = await decrypt(
      fixtures.decryptKeyring(),
      Buffer.from(fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(), 'base64')
    )

    expect(messageHeader.suiteId).to.equal(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
    expect(messageHeader.encryptionContext).to.deep.equal(fixtures.encryptionContext())
    expect(test.toString('base64')).to.equal(fixtures.base64Plaintext())
  })

  it('stream', async () => {
    const ciphertext = Buffer.from(fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(), 'base64')
    const i = ciphertext.values()
    const ciphertextStream = from((_: number, next: Function) => {
      /* Pushing 1 byte at time is the most annoying thing.
       * This is done intentionally to hit _every_ boundary condition.
       */
      const { value, done } = i.next()
      if (done) return next(null, null)
      next(null, new Uint8Array([value]))
    })

    const { plaintext: test, messageHeader } = await decrypt(
      fixtures.decryptKeyring(),
      ciphertextStream
    )

    expect(messageHeader.suiteId).to.equal(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
    expect(messageHeader.encryptionContext).to.deep.equal(fixtures.encryptionContext())
    expect(test.toString('base64')).to.equal(fixtures.base64Plaintext())
  })

  it('Precondition: The sequence number is required to monotonically increase, starting from 1.', async () => {
    return expect(decrypt(
      fixtures.decryptKeyring(),
      fixtures.frameSequenceOutOfOrder(),
      { encoding: 'base64' }
    )).to.rejectedWith(Error, 'Encrypted body sequence out of order.')
  })

  it('Postcondition: The signature must be valid.', async () => {
    await expect(decrypt(
      fixtures.decryptKeyring(),
      fixtures.invalidSignatureCiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(),
      { encoding: 'base64' }
    )).to.rejectedWith(Error, 'Invalid Signature')
  })

  it('can decrypt maxBodySize message with a single final frame.', async () => {
    const { plaintext: test } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.base64Ciphertext4BytesWith4KFrameLength(),
      { encoding: 'base64', maxBodySize: 4 }
    )
    expect(test).to.deep.equal(Buffer.from('asdf'))
  })

  it('will not decrypt data that exceeds maxBodySize.', async () => {
    return expect(decrypt(
      fixtures.decryptKeyring(),
      fixtures.base64Ciphertext4BytesWith4KFrameLength(),
      { encoding: 'base64', maxBodySize: 3 }
    )).to.rejectedWith(Error, 'maxBodySize exceeded.')
  })
})
