/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import {
  NodeDecryptionMaterial, // eslint-disable-line no-unused-vars
  NodeEncryptionMaterial, // eslint-disable-line no-unused-vars
  NodeCryptographicMaterialsManager, NodeKeyring, EncryptedDataKey,
  KeyringTraceFlag, AlgorithmSuiteIdentifier
} from '@aws-crypto/material-management-node'

// import * as fs from 'fs'

import { encrypt } from '@aws-crypto/encrypt-node'
import { decrypt } from '../src/decrypt'

describe('asdf', () => {
  it.only('qwerasdf', async () => {
    class TestKeyring extends NodeKeyring {
      async _onEncrypt (material: NodeEncryptionMaterial) {
        const unencryptedDataKey = new Uint8Array(material.suite.keyLengthBytes).fill(1)
        const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
        const edk = new EncryptedDataKey({ providerId: 'k', providerInfo: 'k', encryptedDataKey: new Uint8Array(3) })
        return material
          .setUnencryptedDataKey(unencryptedDataKey, trace)
          .addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      }
      async _onDecrypt (material: NodeDecryptionMaterial) {
        const unencryptedDataKey = new Uint8Array(material.suite.keyLengthBytes).fill(1)
        const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
        return material.setUnencryptedDataKey(unencryptedDataKey, trace)
      }
    }

    const keyRing = new TestKeyring()
    const cmm = new NodeCryptographicMaterialsManager(keyRing)
    const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16

    const plaintext = 'asdf'
    const ciphertext = await encrypt(cmm, plaintext, { suiteId })

    const {plaintext: test, messageHeader} = await decrypt(cmm, ciphertext)

    expect(messageHeader.algorithmId).to.equal(suiteId)
    expect(test.toString()).to.equal(plaintext)
  })
})
