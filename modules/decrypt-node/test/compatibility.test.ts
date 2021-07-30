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
import { buildDecrypt } from '../src/index'
import * as fixtures from './fixtures'
chai.use(chaiAsPromised)
const { expect } = chai
import {
  CommitmentPolicy,
  MessageFormat,
  needs,
} from '@aws-crypto/material-management'

import { KmsKeyringNode } from '@aws-crypto/kms-keyring-node'

const { decrypt } = buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

describe('committing algorithm test', () => {
  fixtures.compatibilityVectors().tests.forEach((test) => {
    it(test.comment, async () => {
      const {
        ciphertext,
        status,
        'plaintext-frames': plaintextFrames,
        commitment,
        'message-id': messageId,
        'encryption-context': encryptionContext,
      } = test
      const keyring = buildKeyring(test)
      if (status) {
        const { plaintext, messageHeader } = await decrypt(
          keyring,
          ciphertext,
          {
            encoding: 'base64',
          }
        )
        needs(
          plaintextFrames && messageHeader.version === MessageFormat.V2,
          'Message Failure'
        )

        expect(plaintext.toString()).to.equal(plaintextFrames.join(''))
        expect(
          Buffer.from(messageHeader.suiteData).toString('base64')
        ).to.deep.equal(commitment)
        expect(
          Buffer.from(messageHeader.messageId).toString('base64')
        ).to.deep.equal(messageId)
        expect(messageHeader.encryptionContext).to.deep.equal(encryptionContext)
      } else {
        await expect(
          decrypt(keyring, ciphertext, { encoding: 'base64' })
        ).to.rejectedWith(Error)
      }
    })
  })

  function buildKeyring(test: fixtures.VectorTest) {
    if (test['keyring-type'] === 'aws-kms') {
      return new KmsKeyringNode({ discovery: true })
    }
    needs(test['keyring-type'] === 'static', 'wtf yo')
    const dataKey = Buffer.alloc(32, test['decrypted-dek'], 'base64')

    return new (class TestKeyring extends KeyringNode {
      async _onEncrypt(): Promise<NodeEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt(material: NodeDecryptionMaterial) {
        const unencryptedDataKey = dataKey
        const trace = {
          keyNamespace: 'k',
          keyName: 'k',
          flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
        }
        return material.setUnencryptedDataKey(unencryptedDataKey, trace)
      }
    })()
  }
})
