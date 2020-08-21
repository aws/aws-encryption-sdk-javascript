// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { buildDecrypt } from '../src/index'
import {
  needs,
  importForWebCryptoDecryptionMaterial,
  KeyringTraceFlag,
  KeyringWebCrypto,
  WebCryptoDecryptionMaterial,
  WebCryptoEncryptionMaterial,
} from '@aws-crypto/material-management-browser'
import * as fixtures from './fixtures'
import {
  CommitmentPolicy,
  MessageFormat,
} from '@aws-crypto/material-management'
import {
  KmsKeyringBrowser,
  KMS,
  getClient,
} from '@aws-crypto/kms-keyring-browser'
import { fromBase64, toBase64 } from '@aws-sdk/util-base64-browser'
import { toUtf8 } from '@aws-sdk/util-utf8-browser'
chai.use(chaiAsPromised)
const { expect } = chai

const { decrypt } = buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

declare const credentials: {
  accessKeyId: string
  secretAccessKey: string
  sessionToken: string
}
const clientProvider = getClient(KMS, { credentials })

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
          fromBase64(ciphertext)
        )
        needs(
          plaintextFrames && messageHeader.version === MessageFormat.V2,
          'Message Failure'
        )

        expect(toUtf8(plaintext)).to.equal(plaintextFrames.join(''))
        expect(toBase64(messageHeader.suiteData)).to.deep.equal(commitment)
        expect(toBase64(messageHeader.messageId)).to.deep.equal(messageId)
        expect(messageHeader.encryptionContext).to.deep.equal(encryptionContext)
      } else {
        await expect(decrypt(keyring, fromBase64(ciphertext))).to.rejectedWith(
          Error
        )
      }
    })
  })

  function buildKeyring(test: fixtures.VectorTest) {
    if (test['keyring-type'] === 'aws-kms') {
      return new KmsKeyringBrowser({ discovery: true, clientProvider })
    }
    needs(test['keyring-type'] === 'static', 'not aws-kms? not static?')
    const dataKey = fromBase64(test['decrypted-dek'])

    return new (class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt(material: WebCryptoDecryptionMaterial) {
        const unencryptedDataKey = dataKey
        return importForWebCryptoDecryptionMaterial(
          material.setUnencryptedDataKey(unencryptedDataKey, {
            keyNamespace: 'k',
            keyName: 'k',
            flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
          })
        )
      }
    })()
  }
})
