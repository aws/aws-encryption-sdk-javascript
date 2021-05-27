// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
// @ts-ignore
import chaiAsPromised from 'chai-as-promised'
import * as util from 'util'
import * as stream from 'stream'
import { VerifyStream } from '../src/verify_stream'
import { ParseHeaderStream } from '../src/parse_header_stream'
import * as fixtures from './fixtures'
// @ts-ignore
import from from 'from2'
import { ContentType } from '@aws-crypto/serialize'
import {
  AlgorithmSuiteIdentifier,
  needs,
  NodeAlgorithmSuite,
  NodeDefaultCryptographicMaterialsManager,
  SignaturePolicy,
  CommitmentPolicy,
  ClientOptions,
} from '@aws-crypto/material-management-node'

const pipeline = util.promisify(stream.pipeline)
chai.use(chaiAsPromised)
const { expect } = chai

describe('VerifyStream', () => {
  it('can be created', () => {
    const test = new VerifyStream({})
    expect(test).to.be.instanceOf(VerifyStream)
  })

  it('Precondition: VerifyStream requires maxBodySize must be falsey or a number.', () => {
    expect(() => new VerifyStream({ maxBodySize: true } as any)).to.throw(
      'Unsupported MaxBodySize.'
    )
  })

  it('Precondition: The source must a ParseHeaderStream emit the required events.', () => {
    const notParseHeaderStream = from(() => {})
    const test = new VerifyStream({})
    expect(() => notParseHeaderStream.pipe(test)).to.throw('Unsupported source')
  })

  it('Precondition: If maxBodySize was set I can not buffer more data than maxBodySize.', () => {
    const source = new ParseHeaderStream(
      SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
      {
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        maxEncryptedDataKeys: false,
      } as ClientOptions,
      {} as any
    )
    const test = new VerifyStream({ maxBodySize: 1 })
    source.pipe(test)
    // this is _just_ enough data to pass....
    source.emit('VerifyInfo', {
      headerInfo: {
        algorithmSuite: new NodeAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
        ),
        messageHeader: {
          messageId: Buffer.from('asdf'),
          contentType: ContentType.FRAMED_DATA,
          frameLength: 2,
        },
      },
    })

    const buffer = Buffer.concat([
      fixtures.basicFrameHeader(),
      Buffer.from([1]),
    ])
    expect(() => test._transform(buffer, 'binary', () => {})).to.throw(
      'maxBodySize exceeded.'
    )
  })

  it('Precondition: VerifyInfo must have initialized the stream.', () => {
    const test = new VerifyStream({})
    expect(() =>
      test._transform(Buffer.from([1]), 'binary', () => {})
    ).to.throw(
      'VerifyStream not configured, VerifyInfo event not yet received.'
    )
  })

  it('Check for early return (Postcondition): If there is no verify stream do not attempt to verify.', () => {
    // This works because there is no state, and any state would cause _flush to throw
    const test = new VerifyStream({})
    // test.
    let called = false
    test._flush(() => {
      called = true
    })
    expect(called).to.equal(true)
  })

  it('Precondition: All ciphertext MUST have been received.', async () => {
    const cmm = new NodeDefaultCryptographicMaterialsManager(
      fixtures.decryptKeyring()
    )
    const data = Buffer.from(
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfWith4Frames(),
      'base64'
    )
    const completeHeaderLength = 73

    // First we make sure that the test vector is well formed
    await testStream(cmm, data)

    // This make sure we still get nice errors when composed
    for (let i = 0; completeHeaderLength > i; i++) {
      await expect(testStream(cmm, data.slice(0, i))).rejectedWith(
        Error,
        'Incomplete Header'
      )
    }

    // This is the real test, after the header the body MUST be complete
    for (let i = completeHeaderLength; data.byteLength > i; i++) {
      await expect(testStream(cmm, data.slice(0, i))).rejectedWith(
        Error,
        'Incomplete message'
      )
    }
  })

  it('Precondition: The signature must be well formed.', async () => {
    const cmm = new NodeDefaultCryptographicMaterialsManager(
      fixtures.decryptKeyring()
    )
    const data = Buffer.from(
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384With4Frames(),
      'base64'
    )
    const completeHeaderLength = 168
    const lengthToFooter = 340

    // First we make sure that the test vector is well formed
    await testStream(cmm, data)

    // This make sure we still get nice errors when composed
    for (let i = 0; completeHeaderLength > i; i++) {
      await expect(testStream(cmm, data.slice(0, i))).rejectedWith(
        Error,
        'Incomplete Header'
      )
    }

    // This is similar to the test above, and in included for completeness
    for (let i = completeHeaderLength; lengthToFooter > i; i++) {
      await expect(testStream(cmm, data.slice(0, i))).rejectedWith(
        Error,
        'Incomplete message'
      )
    }

    // This is the real test, the signature must be well formed
    for (let i = lengthToFooter; data.byteLength > i; i++) {
      await expect(testStream(cmm, data.slice(0, i))).rejectedWith(
        Error,
        'Invalid Signature'
      )
    }
  })
})

async function testStream(
  cmm: NodeDefaultCryptographicMaterialsManager,
  data: Buffer
) {
  const source = new ParseHeaderStream(
    SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
    {
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      maxEncryptedDataKeys: false,
    } as ClientOptions,
    cmm
  )
  const test = new VerifyStream({})
  let DecipherInfoEmitted = false
  let BodyInfoEmitted = false
  let AuthTagEmitted = false
  test
    .on('DecipherInfo', (d) => {
      DecipherInfoEmitted = !!d
    })
    .on('BodyInfo', (b) => {
      BodyInfoEmitted = !!b
    })
    .on('AuthTag', (a, next) => {
      AuthTagEmitted = !!a
      next()
    })
  source.end(data)
  return pipeline(source, test).then(() => {
    needs(
      DecipherInfoEmitted && BodyInfoEmitted && AuthTagEmitted,
      'Required events not emitted.'
    )
  })
}
