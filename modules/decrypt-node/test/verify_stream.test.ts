// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as util from 'util'
import * as stream from 'stream'
const pipeline = util.promisify(stream.pipeline)
import { VerifyStream } from '../src/verify_stream'
import { ParseHeaderStream } from '../src/parse_header_stream'
import * as fixtures from './fixtures'
import from from 'from2'
import { ContentType } from '@aws-crypto/serialize'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  NodeDefaultCryptographicMaterialsManager,
  needs,
} from '@aws-crypto/material-management-node'
import { CommitmentPolicy } from '@aws-crypto/material-management'
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
      CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
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

  it('Precondition: A complete signature is required to verify.', async () => {
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
        'Incomplete signature'
      )
    }
  })

  it('Precondition: Only buffer data if a signature is expected.', async () => {
    const cmm = new NodeDefaultCryptographicMaterialsManager(
      fixtures.decryptKeyring()
    )
    const data = Buffer.from(
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfWith4Frames(),
      'base64'
    )

    // First we make sure that the test vector is well formed
    await testStream(cmm, data)

    await expect(testStream(cmm, data, Buffer.alloc(1))).rejectedWith(
      Error,
      'Too much data'
    )
  })

  it('Precondition: Only buffer data if the finalAuthTag has been received.', async () => {
    const cmm = new NodeDefaultCryptographicMaterialsManager(
      fixtures.decryptKeyring()
    )
    const data = Buffer.from(
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfWith4Frames(),
      'base64'
    )

    // First we make sure that the test vector is well formed
    await testStream(cmm, data)

    const source = new ParseHeaderStream(
      CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      cmm
    )
    const test = new VerifyStream({})

    /* This is a little ridiculous.
     * The _transform function
     * will only delicate to _transformSignature
     * **after** the finalAuthTag has been received.
     * So this condition is _impossible_.
     * But if it is a good check,
     * then there should be a test... sigh.
     */
    setImmediate(() => {
      source.write(data, () => {
        test._transformSignature(Buffer.alloc(1), 'binary', (e?: Error) => {
          test.emit('error', e)
        })
      })
    })

    await expect(pipeline(source, test)).rejectedWith(Error, 'Malformed state.')
  })
})

async function testStream(
  cmm: NodeDefaultCryptographicMaterialsManager,
  ...data: Buffer[]
) {
  const source = new ParseHeaderStream(
    CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
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
  setImmediate(() => {
    const tail = data.pop()
    data.forEach((data) => source.write(data))
    source.end(tail)
  })
  return pipeline(source, test).then(() => {
    needs(
      DecipherInfoEmitted && BodyInfoEmitted && AuthTagEmitted,
      'Required events not emitted.'
    )
  })
}
