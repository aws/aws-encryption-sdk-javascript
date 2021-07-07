// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
// @ts-ignore
import chaiAsPromised from 'chai-as-promised'
import {
  AlgorithmSuiteIdentifier,
  CommitmentPolicy,
} from '@aws-crypto/material-management-node'
import { buildDecrypt } from '../src/index'
import * as fixtures from './fixtures'
chai.use(chaiAsPromised)
const { expect } = chai
// @ts-ignore
import from from 'from2'
const { decrypt } = buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

describe('decrypt', () => {
  it('string with encoding', async () => {
    const { plaintext: test, messageHeader } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(),
      { encoding: 'base64' }
    )

    expect(messageHeader.suiteId).to.equal(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    expect(messageHeader.encryptionContext).to.deep.equal(
      fixtures.encryptionContext()
    )
    expect(test.toString('base64')).to.equal(fixtures.base64Plaintext())
  })

  it('buffer', async () => {
    const { plaintext: test, messageHeader } = await decrypt(
      fixtures.decryptKeyring(),
      Buffer.from(
        fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(),
        'base64'
      )
    )

    expect(messageHeader.suiteId).to.equal(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    expect(messageHeader.encryptionContext).to.deep.equal(
      fixtures.encryptionContext()
    )
    expect(test.toString('base64')).to.equal(fixtures.base64Plaintext())
  })

  it('stream', async () => {
    const ciphertext = Buffer.from(
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(),
      'base64'
    )

    /* Pushing 1 byte at time is annoying.
     * But there can be state that can get reset
     * from a 1 byte push when the buffering
     * is internal to the stream.
     * So while 1 byte will hit the beginning
     * boundary conditions,
     * and the exiting boundary conditions,
     * but it will never span any boundary conditions.
     * The prime example of this is
     * the `VerifyStream`.
     * It has 4 byte boundary in the `_transform` function.
     * The body header, the body, the auth tag, and signature.
     * By sending 1 byte
     * as the code transitions from the body header
     * to the body
     * the code handling the exiting
     * of the body header has no way to interact
     * with the body,
     * because the 1 byte of data
     * completely isolates these code branches.
     * So I push at different sizes to hit
     * as many boundary conditions as possible.
     * Why 20 as a max?
     * Permuting every possible combination
     * would take too long
     * and so anything short of _everything_
     * is a compromise.
     * 20 seems large enough.
     * I did not do an initial offset
     * because that just moves me closer
     * to permuting every option.
     * An alternative would be a variable chunk size.
     * Doing this randomly is a bad idea.
     * Tests that only fail _sometimes_
     * are bad tests.
     * It is too easy to try again,
     * and when everything passes just move on.
     * And again, doing every permutation
     * is too expensive at this time.
     */
    const results = await Promise.all(
      [
        { size: 1 },
        { size: 2 },
        { size: 3 },
        { size: 4 },
        { size: 5 },
        { size: 6 },
        { size: 7 },
        { size: 8 },
        { size: 9 },
        { size: 10 },
        { size: 11 },
        { size: 12 },
        { size: 13 },
        { size: 14 },
        { size: 15 },
        { size: 16 },
        { size: 17 },
        { size: 18 },
        { size: 19 },
        { size: 20 },
      ].map(async (op) =>
        decrypt(
          fixtures.decryptKeyring(),
          chunkCipherTextStream(ciphertext, op)
        )
      )
    )

    results.map(({ plaintext: test, messageHeader }) => {
      expect(messageHeader.suiteId).to.equal(
        AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
      )
      expect(messageHeader.encryptionContext).to.deep.equal(
        fixtures.encryptionContext()
      )
      expect(test.toString('base64')).to.equal(fixtures.base64Plaintext())
    })
  })

  it('Precondition: The sequence number is required to monotonically increase, starting from 1.', async () => {
    return expect(
      decrypt(fixtures.decryptKeyring(), fixtures.frameSequenceOutOfOrder(), {
        encoding: 'base64',
      })
    ).to.rejectedWith(Error, 'Encrypted body sequence out of order.')
  })

  it('Postcondition: The signature must be valid.', async () => {
    await expect(
      decrypt(
        fixtures.decryptKeyring(),
        fixtures.invalidSignatureCiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(),
        { encoding: 'base64' }
      )
    ).to.rejectedWith(Error, 'Invalid Signature')
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
    return expect(
      decrypt(
        fixtures.decryptKeyring(),
        fixtures.base64Ciphertext4BytesWith4KFrameLength(),
        { encoding: 'base64', maxBodySize: 3 }
      )
    ).to.rejectedWith(Error, 'maxBodySize exceeded.')
  })

  it('can decrypt data with less than maxEncryptedDataKeys', async () => {
    const { decrypt } = buildDecrypt({
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      maxEncryptedDataKeys: 3,
    })
    const { plaintext } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.twoEdksMessage(),
      { encoding: 'base64' }
    )
    expect(plaintext).to.deep.equal(Buffer.from('asdf'))
  })

  it('can decrypt data with exactly maxEncryptedDataKeys', async () => {
    const { decrypt } = buildDecrypt({
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      maxEncryptedDataKeys: 3,
    })
    const { plaintext } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.threeEdksMessage(),
      { encoding: 'base64' }
    )
    expect(plaintext).to.deep.equal(Buffer.from('asdf'))
  })

  it('will not decrypt data with more than maxEncryptedDataKeys', async () => {
    const { decrypt } = buildDecrypt({
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      maxEncryptedDataKeys: 3,
    })
    await expect(
      decrypt(fixtures.decryptKeyring(), fixtures.fourEdksMessage(), {
        encoding: 'base64',
      })
    ).to.rejectedWith(Error, 'maxEncryptedDataKeys exceeded.')
  })
})

function chunkCipherTextStream(ciphertext: Buffer, { size }: { size: number }) {
  const i = ciphertext.values()

  return from(
    (
      _: number,
      next: (err: Error | null, chunk: Uint8Array | null) => void
    ) => {
      const { value, done } = eat(i, size)
      if (done) return next(null, null)
      next(null, new Uint8Array(value))
    }
  )

  function eat(i: IterableIterator<number>, size: number) {
    return Array(size)
      .fill(1)
      .reduce<IteratorResult<number[], any>>(
        ({ value }) => {
          const { value: item, done } = i.next()
          if (done && value.length) return { value, done: false }
          if (!done) value.push(item)
          return { value, done }
        },
        { value: <number[]>[], done: false }
      )
  }
}
