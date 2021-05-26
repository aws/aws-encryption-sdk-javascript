// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
// @ts-ignore
import chaiAsPromised from 'chai-as-promised'
import * as util from 'util'
import * as stream from 'stream'
import { ParseHeaderStream } from '../src/parse_header_stream'
import {
  NodeAlgorithmSuite,
  NodeDecryptionMaterial,
  NodeDefaultCryptographicMaterialsManager,
  AlgorithmSuiteIdentifier,
  needs,
  SignaturePolicy,
  CommitmentPolicy,
  ClientOptions,
} from '@aws-crypto/material-management-node'
import * as fixtures from './fixtures'

const pipeline = util.promisify(stream.pipeline)
chai.use(chaiAsPromised)
const { expect } = chai

describe('ParseHeaderStream', () => {
  it('can be constructed', () => {
    const cmm = {} as any
    const test = new ParseHeaderStream(
      SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
      {
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        maxEncryptedDataKeys: false,
      } as ClientOptions,
      cmm
    )
    expect(test).to.have.property('materialsManager').and.to.eql(cmm)
    expect(test)
      .to.have.property('commitmentPolicy')
      .and.to.eql(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    expect(test).to.have.property('maxEncryptedDataKeys').and.to.eql(false)
  })

  it('Precondition: ParseHeaderStream needs a valid maxEncryptedDataKeys.', () => {
    expect(
      () =>
        new ParseHeaderStream(
          SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
          {
            commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            maxEncryptedDataKeys: 0,
          } as ClientOptions,
          {} as any
        )
    ).to.throw('Invalid maxEncryptedDataKeys value.')
  })

  describe('supports commitmentPolicy', () => {
    it('Precondition: ParseHeaderStream needs a valid commitmentPolicy.', () => {
      expect(
        () =>
          new ParseHeaderStream(
            SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
            {
              commitmentPolicy: {} as any,
              maxEncryptedDataKeys: false,
            } as ClientOptions,
            {} as any
          )
      ).to.throw('Invalid commitment policy.')
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
        testStream({
          cmm: cmm,
          data: data,
          commitmentPolicy: CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
          maxEncryptedDataKeys: false,
        })
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
        testStream({
          cmm: cmm,
          data: data,
          commitmentPolicy: CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        })
      ).to.rejectedWith(
        Error,
        'Configuration conflict. Cannot process message with ID'
      )

      expect(called_decryptMaterials).to.equal(true)
    })
  })

  describe('supports signaturePolicy', () => {
    const cmm = new NodeDefaultCryptographicMaterialsManager(
      fixtures.decryptKeyring()
    )
    // @ts-ignore
    function parseHeaderStreamWithSignaturePolicy(signaturePolicy?) {
      return new ParseHeaderStream(
        signaturePolicy,
        {
          commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
          maxEncryptedDataKeys: false,
        } as ClientOptions,
        cmm
      )
    }

    it('Precondition: ParseHeaderStream needs a valid signaturePolicy.', () => {
      expect(() => parseHeaderStreamWithSignaturePolicy({} as any)).to.throw(
        'Invalid signature policy.'
      )
    })

    it('Precondition: The parsed header algorithmSuite from ParseHeaderStream must be supported by the signaturePolicy.', async () => {
      const data = Buffer.from(
        fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384(),
        'base64'
      )

      await expect(
        testStream({
          cmm: cmm,
          data: data,
          signaturePolicy: SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT,
        })
      ).to.rejectedWith(
        Error,
        'Configuration conflict. Cannot process message with ID'
      )
    })

    it('Precondition: The material algorithmSuite returned to ParseHeaderStream must be supported by the signaturePolicy.', async () => {
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
        testStream({
          cmm: cmm,
          data: data,
          signaturePolicy: SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT,
        })
      ).to.rejectedWith(
        Error,
        'Configuration conflict. Cannot process message with ID'
      )

      expect(called_decryptMaterials).to.equal(true)
    })
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
        testStream({
          cmm: cmm,
          data: data.slice(0, i),
          commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        })
      ).rejectedWith(Error, 'Incomplete Header')
    }

    for (let i = completeHeaderLength; data.byteLength > i; i++) {
      await testStream({
        cmm: cmm,
        data: data.slice(0, i),
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      })
    }
  })

  it('Exceptional Postcondition: An error MUST be emitted or this would be an unhandled exception.', async () => {
    const data = Buffer.from(
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384With4Frames(),
      'base64'
    )
    let called_decryptMaterials = false
    const cmm = {
      async decryptMaterials() {
        called_decryptMaterials = true
        throw new Error('Valid Error')
      },
    } as any

    await expect(
      testStream({
        cmm: cmm,
        data: data,
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      })
    ).to.rejectedWith(Error, 'Valid Error')

    expect(called_decryptMaterials).to.equal(true)
  })
})

interface TestStreamParams {
  cmm: NodeDefaultCryptographicMaterialsManager
  data: Buffer
  commitmentPolicy?: CommitmentPolicy
  signaturePolicy?: SignaturePolicy
  maxEncryptedDataKeys?: number | false
}

async function testStream({
  cmm,
  data,
  commitmentPolicy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
  signaturePolicy = SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
  maxEncryptedDataKeys = false,
}: TestStreamParams): Promise<void> {
  let VerifyInfoEmitted = false
  let MessageHeaderEmitted = false
  const parseHeader = new ParseHeaderStream(
    signaturePolicy,
    {
      commitmentPolicy: commitmentPolicy,
      maxEncryptedDataKeys: maxEncryptedDataKeys,
    } as ClientOptions,
    cmm
  )
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
