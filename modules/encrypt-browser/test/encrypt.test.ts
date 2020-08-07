// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  WebCryptoDecryptionMaterial,
  WebCryptoEncryptionMaterial,
  KeyringWebCrypto,
  EncryptedDataKey,
  WebCryptoAlgorithmSuite,
  importForWebCryptoEncryptionMaterial,
} from '@aws-crypto/material-management-browser'
import {
  deserializeFactory,
  decodeBodyHeader,
  deserializeSignature,
} from '@aws-crypto/serialize'
import { encrypt } from '../src/index'
import { toUtf8, fromUtf8 } from '@aws-sdk/util-utf8-browser'

chai.use(chaiAsPromised)
const { expect } = chai

const { deserializeMessageHeader } = deserializeFactory(
  toUtf8,
  WebCryptoAlgorithmSuite
)

/* These tests only check structure.
 * see decrypt-node for actual cryptographic tests
 * see integration-node for exhaustive compatibility tests
 */
describe('encrypt structural testing', () => {
  const edk = new EncryptedDataKey({
    providerId: 'k',
    providerInfo: 'k',
    encryptedDataKey: new Uint8Array(3),
    /* rawInfo added because it will always be there when deserialized.
     * This way deep equal will pass nicely.
     * 107 is 'k' in ASCII
     */
    rawInfo: new Uint8Array([107]),
  })
  class TestKeyring extends KeyringWebCrypto {
    async _onEncrypt(material: WebCryptoEncryptionMaterial) {
      const unencryptedDataKey = new Uint8Array(
        material.suite.keyLengthBytes
      ).fill(0)

      material
        .setUnencryptedDataKey(unencryptedDataKey)
        .addEncryptedDataKey(edk)
      return importForWebCryptoEncryptionMaterial(material)
    }
    async _onDecrypt(): Promise<WebCryptoDecryptionMaterial> {
      throw new Error('I should never see this error')
    }
  }

  const keyRing = new TestKeyring()

  it('encrypt an ArrayBuffer', async () => {
    const encryptionContext = { simple: 'context' }

    const plaintext = fromUtf8('asdf')
    const { result, messageHeader } = await encrypt(keyRing, plaintext, {
      encryptionContext,
    })

    /* The default algorithm suite will add a signature key to the context.
     * So I only check that the passed context elements exist.
     */
    expect(messageHeader.encryptionContext)
      .to.haveOwnProperty('simple')
      .and.to.equal('context')
    expect(messageHeader.encryptedDataKeys).lengthOf(1)
    expect(messageHeader.encryptedDataKeys[0]).to.deep.equal(edk)

    const messageInfo = deserializeMessageHeader(result)
    if (!messageInfo) throw new Error('I should never see this error')

    expect(messageHeader).to.deep.equal(messageInfo.messageHeader)
  })

  it('Precondition: The ESDK reserves an encryption context namespace for browser CMMs.', () => {
    const encryptionContext = {
      'aws-crypto-is-a': 'reserved namespace',
    }
    expect(() =>
      encrypt(keyRing, fromUtf8('asdf'), { encryptionContext })
    ).to.throw('Encryption context keys that start with')
  })

  it('Precondition: The frameLength must be less than the maximum frame size for browser encryption.', async () => {
    const frameLength = 0
    await expect(
      encrypt(keyRing, fromUtf8('asdf'), { frameLength })
    ).to.rejectedWith(Error)
  })

  it('can fully parse a framed message', async () => {
    const plaintext = fromUtf8('asdf')
    const frameLength = 1
    const { result } = await encrypt(keyRing, plaintext, { frameLength })

    const headerInfo = deserializeMessageHeader(result)
    if (!headerInfo) throw new Error('this should never happen')

    const tagLength = headerInfo.algorithmSuite.tagLength / 8
    let readPos =
      headerInfo.headerLength + headerInfo.algorithmSuite.ivLength + tagLength
    let i = 0
    let bodyHeader: any
    // for every frame...
    for (; i < 4; i++) {
      bodyHeader = decodeBodyHeader(result, headerInfo, readPos)
      if (!bodyHeader) throw new Error('this should never happen')
      readPos = bodyHeader.readPos + bodyHeader.contentLength + tagLength
    }

    expect(i).to.equal(4) // 4 frames
    expect(bodyHeader.isFinalFrame).to.equal(true) // we got to the end

    // This implicitly tests that I have consumed all the data,
    // because otherwise the footer section will be too large
    const footerSection = result.slice(readPos)
    // This will throw if it does not deserialize correctly
    deserializeSignature(footerSection)
  })
})
