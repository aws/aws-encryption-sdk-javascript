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
})
