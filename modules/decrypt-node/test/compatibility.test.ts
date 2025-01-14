// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
// @ts-ignore
import chaiAsPromised from 'chai-as-promised'
import {
  KeyringNode,
  KeyringTraceFlag,
  NodeDecryptionMaterial,
  NodeEncryptionMaterial,
} from '@aws-crypto/material-management-node'
import { buildDecrypt, DecryptOutput } from '../src/index'
import { buildEncrypt } from '@aws-crypto/encrypt-node'
import * as fixtures from './fixtures'
chai.use(chaiAsPromised)
const { expect } = chai
import {
  AlgorithmSuiteIdentifier,
  CommitmentPolicy,
  MessageFormat,
  needs,
  NodeBranchKeyMaterial,
} from '@aws-crypto/material-management'

import {
  KmsHierarchicalKeyRingNode,
  KmsKeyringNode,
} from '@aws-crypto/kms-keyring-node'
import { BranchKeyStoreNode } from '@aws-crypto/branch-keystore-node'

const { decrypt } = buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
const { encrypt } = buildEncrypt(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)

describe('committing algorithm test', () => {
  fixtures.compatibilityVectors().tests.forEach((test) => {
    it(test.comment, async () => {
      const { ciphertext, status } = test
      const keyring = buildKeyring(test)
      if (status) {
        const output = await decrypt(keyring, ciphertext, {
          encoding: 'base64',
        })

        ExpectCompatibilityVector(test, output)
      } else {
        await expect(
          decrypt(keyring, ciphertext, { encoding: 'base64' })
        ).to.rejectedWith(Error)
      }
    })
  })

  fixtures.hierarchicalKeyringCompatibilityVectors().tests.forEach((test) => {
    it(`Decrypt test: ${test.comment}`, async () => {
      const { ciphertext, status } = test
      const keyring = buildKeyring(test)
      needs(status, 'Unexpected Status')
      const output = await decrypt(keyring, ciphertext, {
        encoding: 'base64',
      })

      ExpectCompatibilityVector(test, output)
    })
  })

  fixtures.hierarchicalKeyringCompatibilityVectors().tests.forEach((test) => {
    let once = false
    it(`Encrypt test: ${test.comment}`, async () => {
      const { plaintextBase64, status } = test
      const keyring = buildKeyring(test)
      needs(status, 'Unexpected Status')
      needs(plaintextBase64, 'Nothing to encrypt')

      const suiteId = once
        ? AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
        : AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
      once = true

      const encryptOutput = await encrypt(keyring, plaintextBase64, {
        encoding: 'base64',
        suiteId,
      })

      const decryptOutput = await decrypt(keyring, encryptOutput.result)
      expect(decryptOutput.plaintext.toString('base64')).to.equal(
        plaintextBase64
      )
    })
  })

  function ExpectCompatibilityVector(
    {
      'plaintext-frames': plaintextFrames,
      plaintextBase64,
      commitment,
      'message-id': messageId,
      'encryption-context': encryptionContext,
    }: fixtures.VectorTest,
    { plaintext, messageHeader }: DecryptOutput
  ) {
    needs(messageHeader.version === MessageFormat.V2, 'Message Failure')

    if (plaintextBase64) {
      expect(plaintext.toString('base64')).to.equal(plaintextBase64)
    }
    if (plaintextFrames) {
      expect(plaintext.toString()).to.equal(plaintextFrames.join(''))
    }
    expect(
      Buffer.from(messageHeader.suiteData).toString('base64')
    ).to.deep.equal(commitment)
    expect(
      Buffer.from(messageHeader.messageId).toString('base64')
    ).to.deep.equal(messageId)
    expect(messageHeader.encryptionContext).to.deep.equal(encryptionContext)
  }

  function buildKeyring(test: fixtures.VectorTest) {
    switch (test['keyring-type']) {
      case 'aws-kms':
        return new KmsKeyringNode({ discovery: true })
      case 'static':
        return new (class TestKeyring extends KeyringNode {
          async _onEncrypt(): Promise<NodeEncryptionMaterial> {
            throw new Error('I should never see this error')
          }
          async _onDecrypt(material: NodeDecryptionMaterial) {
            const unencryptedDataKey = Buffer.alloc(
              32,
              test['decrypted-dek'],
              'base64'
            )
            const trace = {
              keyNamespace: 'k',
              keyName: 'k',
              flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
            }
            return material.setUnencryptedDataKey(unencryptedDataKey, trace)
          }
        })()

      case 'static-branch-key':
        // This is serious hackery.
        // This is *NOT* recommended.
        // The proper extension point for the KeyStore is _only_ the Storage interface!
        // However, this does let us do some quick test vector testing.
        // At this time this is overly prescriptive,
        // but the expectation is to be able to deprecate this
        // in favor of the test vectors project (integration-node)
        return new KmsHierarchicalKeyRingNode({
          branchKeyId: 'bd3842ff-3076-4092-9918-4395730050b8',
          cacheLimitTtl: 1,
          keyStore: {
            __proto__: BranchKeyStoreNode.prototype,
            kmsConfiguration: {
              getRegion() {
                return null
              },
            },

            getKeyStoreInfo() {
              return {
                logicalKeyStoreName: 'logicalKeyStoreName',
              }
            },

            async getBranchKeyVersion(
              branchKeyId: string,
              branchKeyVersion: string
            ): Promise<NodeBranchKeyMaterial> {
              needs(
                branchKeyId == 'bd3842ff-3076-4092-9918-4395730050b8',
                branchKeyId
              )
              needs(
                branchKeyVersion == 'e9ce18a3-edb5-4272-9f86-1cacb7997ff6',
                branchKeyVersion
              )

              return new NodeBranchKeyMaterial(
                Buffer.from(
                  'tJwf65epYvUt5HMiQsl/6jlvLxS0tgdjIuvFy2BLIwg=',
                  'base64'
                ),
                branchKeyId,
                branchKeyVersion,
                {}
              )
            },
            async getActiveBranchKey(
              branchKeyId: string
            ): Promise<NodeBranchKeyMaterial> {
              needs(
                branchKeyId == 'bd3842ff-3076-4092-9918-4395730050b8',
                branchKeyId
              )

              return new NodeBranchKeyMaterial(
                Buffer.from(
                  'tJwf65epYvUt5HMiQsl/6jlvLxS0tgdjIuvFy2BLIwg=',
                  'base64'
                ),
                branchKeyId,
                'e9ce18a3-edb5-4272-9f86-1cacb7997ff6',
                {}
              )
            },

            storage: {
              _config: {},
              getKeyStorageInfo() {
                return {
                  logicalName: 'logicalKeyStoreName',
                }
              },
            },
          } as any,
        })
    }

    needs(false, 'Unexpected keyring-type:' + test['keyring-type'])
  }
})
