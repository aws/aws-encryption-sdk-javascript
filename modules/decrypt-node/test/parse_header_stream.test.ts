// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import * as util from 'util'
import * as stream from 'stream'
const pipeline = util.promisify(stream.pipeline)
import { ParseHeaderStream } from '../src/parse_header_stream'
import {
  NodeAlgorithmSuite,
  NodeDecryptionMaterial,
  AlgorithmSuiteIdentifier,
  NodeDefaultCryptographicMaterialsManager,
  needs,
} from '@aws-crypto/material-management-node'
import { CommitmentPolicy } from '@aws-crypto/material-management'
import * as fixtures from './fixtures'
chai.use(chaiAsPromised)
const { expect } = chai

describe('ParseHeaderStream', () => {
  it('can be constructed', () => {
    const cmm = {} as any
    const test = new ParseHeaderStream(
      CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      cmm
    )
    expect(test).to.have.property('materialsManager').and.to.eql(cmm)
    expect(test)
      .to.have.property('commitmentPolicy')
      .and.to.eql(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
  })

  it('Precondition: ParseHeaderStream needs a valid commitmentPolicy.', () => {
    expect(() => new ParseHeaderStream({} as any, {} as any)).to.throw(
      'Invalid commitment policy.'
    )
  })

  it('Precondition: The parsed header algorithmSuite from ParseHeaderStream must be supported by the commitmentPolicy.', async () => {
    const cmm = new NodeDefaultCryptographicMaterialsManager(
      fixtures.decryptKeyring()
    )
    const data = Buffer.from(
      fixtures.base64Ciphertext4BytesWith4KFrameLength(),
      'base64'
    )

    await expect(
      testStream(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, cmm, data)
    ).to.rejectedWith(
      Error,
      'Configuration conflict. Cannot process message with ID'
    )
  })

  it('Precondition: The material algorithmSuite returned to ParseHeaderStream must be supported by the commitmentPolicy.', async () => {
    let called_decryptMaterials = false
    const cmm = {
      async decryptMaterials() {
        called_decryptMaterials = true
        const suite = new NodeAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
        )
        return new NodeDecryptionMaterial(suite, {})
      },
    } as any
    const data = Buffer.from(
      fixtures.compatibilityVectors().tests[0].ciphertext,
      'base64'
    )

    await expect(
      testStream(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, cmm, data)
    ).to.rejectedWith(
      Error,
      'Configuration conflict. Cannot process message with ID'
    )

    expect(called_decryptMaterials).to.equal(true)
  })

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
      await expect(
        testStream(
          CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
          cmm,
          data.slice(0, i)
        )
      ).rejectedWith(Error, 'Incomplete Header')
    }

    for (let i = completeHeaderLength; data.byteLength > i; i++) {
      await testStream(
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        cmm,
        data.slice(0, i)
      )
    }
  })
})

async function testStream(
  commitmentPolicy: CommitmentPolicy,
  cmm: NodeDefaultCryptographicMaterialsManager,
  data: Buffer
) {
  let VerifyInfoEmitted = false
  let MessageHeaderEmitted = false
  const parseHeader = new ParseHeaderStream(commitmentPolicy, cmm)
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
