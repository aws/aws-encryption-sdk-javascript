/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// import { expect } from 'chai'
import 'mocha'
import {
  NodeDecryptionMaterial, // eslint-disable-line no-unused-vars
  NodeAlgorithmSuite, NodeEncryptionMaterial, NodeCryptographicMaterialsManager, KeyringNode, EncryptedDataKey,
  KeyringTraceFlag, AlgorithmSuiteIdentifier
} from '@aws-crypto/material-management-node'

import * as fs from 'fs'

import { encryptStream, getEncryptionInfo } from '../src/encrypt_stream'

import { getFramedEncryptStream } from '../src/framed_encrypt_stream'
import { SignatureStream } from '../src/signature_stream'
import { encrypt } from '../src/encrypt'

const never = () => { throw new Error('never') }

describe('asdf', () => {
  it.skip('encrypt', async () => {
    class TestKeyring extends KeyringNode {
      async _onEncrypt (material: NodeEncryptionMaterial) {
        const unencryptedDataKey = new Uint8Array(material.suite.keyLengthBytes).fill(1)
        const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
        const edk = new EncryptedDataKey({ providerId: 'k', providerInfo: 'k', encryptedDataKey: new Uint8Array(3) })
        return material
          .setUnencryptedDataKey(unencryptedDataKey, trace)
          .addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      }
      async _onDecrypt (material: NodeDecryptionMaterial) {
        never()
        return material
      }
    }
    const keyRing = new TestKeyring()
    const cmm = new NodeCryptographicMaterialsManager(keyRing)
    const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16

    const plaintext = 'asdf'
    const ciphertext = await encrypt(cmm, plaintext, { suiteId })
    console.log(ciphertext)
  })

  it.skip('getFramedEncryptStream', (done) => {
    const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    const suite = new NodeAlgorithmSuite(suiteId)
    const material = new NodeEncryptionMaterial(suite)

    const unencryptedDataKey = new Uint8Array(material.suite.keyLengthBytes).fill(1)
    const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
    const edk = new EncryptedDataKey({ providerId: 'k', providerInfo: 'k', encryptedDataKey: new Uint8Array(3) })
    material
      .setUnencryptedDataKey(unencryptedDataKey, trace)
      .addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)

    const { getCipher, messageHeader } = getEncryptionInfo(material, 1048, {})

    const stream = getFramedEncryptStream(getCipher, messageHeader, () => {})

    // 1048576

    const stats = {
      rawFile: 0,
      encrypt: 0,
      sig: 0
    }

    fs.createReadStream('/Users/ryanemer/aws-encryption-sdk-javascript/modules/encrypt-node/20190124_213050.jpg')
      .on('data', ({ length }) => { stats.rawFile += length })
      .pipe(stream)
      .on('data', ({ length }) => { stats.encrypt += length })
      .pipe(new SignatureStream())
      .on('data', ({ length }) => { stats.sig += length })
      .pipe(fs.createWriteStream('/Users/ryanemer/aws-encryption-sdk-javascript/modules/encrypt-node/stream_only'))
      .on('finish', () => {
        console.log('Stream: ', stats)
        done()
      })
  })

  it.skip('duplex', (done) => {
    class TestKeyring extends KeyringNode {
      async _onEncrypt (material: NodeEncryptionMaterial) {
        const unencryptedDataKey = new Uint8Array(material.suite.keyLengthBytes).fill(1)
        const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
        const edk = new EncryptedDataKey({ providerId: 'k', providerInfo: 'k', encryptedDataKey: new Uint8Array(3) })
        return material
          .setUnencryptedDataKey(unencryptedDataKey, trace)
          .addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      }
      async _onDecrypt (material: NodeDecryptionMaterial) {
        never()
        return material
      }
    }
    const keyRing = new TestKeyring()
    const cmm = new NodeCryptographicMaterialsManager(keyRing)
    const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16

    // 1048576
    const stream = encryptStream(cmm, { suiteId, frameLength: 1048 })

    const stats = {
      rawFile: 0,
      encrypt: 0,
      sig: 0
    }
    fs.createReadStream('/Users/ryanemer/aws-encryption-sdk-javascript/modules/encrypt-node/20190124_213050.jpg')
      .on('data', ({ length }) => { stats.rawFile += length })
      .pipe(stream)
      .on('data', ({ length }) => { stats.encrypt += length })
      .pipe(fs.createWriteStream('/Users/ryanemer/aws-encryption-sdk-javascript/modules/encrypt-node/stream_duplex'))
      .on('finish', () => {
        console.log('Duplex:', stats)
        done()
      })
  })
})
