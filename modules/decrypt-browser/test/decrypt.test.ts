// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { decrypt } from '../src/index'
import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management-browser'
import * as fixtures from './fixtures'

describe('decrypt', () => {
  it('buffer', async () => {
    const { plaintext: test, messageHeader } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.ciphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384()
    )

    expect(messageHeader.suiteId).to.equal(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    expect(messageHeader.encryptionContext).to.deep.equal(
      fixtures.encryptionContext()
    )
    expect(test).to.deep.equal(fixtures.plaintext())
  })

  it('Precondition: The sequenceNumber is required to monotonically increase, starting from 1.', async () => {
    return decrypt(
      fixtures.decryptKeyring(),
      fixtures.frameSequenceOutOfOrder()
    ).then(
      () => {
        throw new Error('should not succeed')
      },
      (err) => {
        expect(err).to.be.instanceOf(Error)
      }
    )
  })

  it('Postcondition: subtleVerify must validate the signature.', async () => {
    return decrypt(
      fixtures.decryptKeyring(),
      fixtures.invalidSignatureCiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384()
    ).then(
      () => {
        throw new Error('should not succeed')
      },
      (err) => {
        expect(err).to.be.instanceOf(Error)
        expect(err.message).to.equal('Invalid Signature')
      }
    )
  })
})
