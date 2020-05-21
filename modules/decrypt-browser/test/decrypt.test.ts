// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { decrypt } from '../src/index'
import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management-browser'
import * as fixtures from './fixtures'
chai.use(chaiAsPromised)
const { expect } = chai

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

  it('verify incomplete chipertext will fail for an un-signed algorithm suite', async () => {
    const data = fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfWith4Frames()
    const keyring = fixtures.decryptKeyring()

    // First we make sure that the test vector is well formed
    await decrypt(keyring, data)

    // This is the real test:
    // trying to decrypt
    // on EVERY boundary
    for (let i = 0; data.byteLength > i; i++) {
      await expect(decrypt(keyring, data.slice(0, i))).to.rejectedWith(Error)
    }
  })

  it('verify incomplete chipertext will fail for a signed algorithm suite', async () => {
    const data = fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384With4Frames()
    const keyring = fixtures.decryptKeyring()

    // First we make sure that the test vector is well formed
    await decrypt(keyring, data)

    // This is the real test:
    // trying to decrypt
    // on EVERY boundary
    for (let i = 0; data.byteLength > i; i++) {
      await expect(decrypt(keyring, data.slice(0, i))).to.rejectedWith(Error)
    }
  })
})
