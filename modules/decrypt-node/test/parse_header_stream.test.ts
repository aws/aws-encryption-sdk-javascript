// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as util from 'util'
import * as stream from 'stream'
const pipeline = util.promisify(stream.pipeline)
import {
  ParseHeaderStream,
  ParseHeaderStreamOptions,
} from '../src/parse_header_stream'
import {
  NodeDefaultCryptographicMaterialsManager,
  needs,
} from '@aws-crypto/material-management-node'
import * as fixtures from './fixtures'
chai.use(chaiAsPromised)
const { expect } = chai

describe('ParseHeaderStream', () => {
  it('Postcondition: A completed header MUST have been processed.', async () => {
    const completeHeaderLength = 73
    const data = Buffer.from(
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfWith4Frames(),
      'base64'
    )
    const cmm = new NodeDefaultCryptographicMaterialsManager(
      fixtures.decryptKeyring()
    )

    for (let i = 0; completeHeaderLength > i; i++) {
      await expect(testStream(cmm, data.slice(0, i))).rejectedWith(
        Error,
        'Incomplete Header'
      )
    }

    for (let i = completeHeaderLength; data.byteLength > i; i++) {
      await testStream(cmm, data.slice(0, i))
    }
  })

  it('Precondition: If maxHeaderSize was set I can not buffer a header larger than maxHeaderSize.', async () => {
    const completeHeaderLength = 73
    const data = Buffer.from(
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfWith4Frames(),
      'base64'
    )
    const cmm = new NodeDefaultCryptographicMaterialsManager(
      fixtures.decryptKeyring()
    )

    for (let i = 1; completeHeaderLength > i; i++) {
      await expect(testStream(cmm, data, { maxHeaderSize: i })).rejectedWith(
        Error,
        'maxHeaderSize exceeded.'
      )
    }

    for (let i = completeHeaderLength; data.byteLength > i; i++) {
      await testStream(cmm, data.slice(0, i), { maxHeaderSize: i })
    }
  })
})

async function testStream(
  cmm: NodeDefaultCryptographicMaterialsManager,
  data: Buffer,
  op: ParseHeaderStreamOptions = {}
) {
  let VerifyInfoEmitted = false
  let MessageHeaderEmitted = false
  const parseHeader = new ParseHeaderStream(cmm, op)
    .on('VerifyInfo', () => {
      VerifyInfoEmitted = true
    })
    .on('MessageHeader', () => {
      MessageHeaderEmitted = true
    })
  parseHeader.end(data)
  return pipeline(parseHeader, new stream.PassThrough()).then(() => {
    needs(
      VerifyInfoEmitted && MessageHeaderEmitted,
      'Required events not emitted.'
    )
  })
}
