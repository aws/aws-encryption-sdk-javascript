// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  NodeDecryptionMaterial,
  NodeEncryptionMaterial,
  KeyringNode,
  EncryptedDataKey,
  KeyringTraceFlag,
  AlgorithmSuiteIdentifier,
  NodeAlgorithmSuite,
  CommitmentPolicy,
} from '@aws-crypto/material-management-node'
import {
  deserializeFactory,
  decodeBodyHeader,
  deserializeSignature,
  MessageHeader,
} from '@aws-crypto/serialize'
import { buildEncrypt } from '../src/index'
import { _encrypt } from '../src/encrypt'
import from from 'from2'
// @ts-ignore
import { finished } from 'readable-stream'
import { randomBytes } from 'crypto'
const { encrypt, encryptStream } = buildEncrypt(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)

chai.use(chaiAsPromised)
const { expect } = chai

const toUtf8 = (input: Uint8Array) =>
  Buffer.from(input.buffer, input.byteOffset, input.byteLength).toString('utf8')
const { deserializeMessageHeader } = deserializeFactory(
  toUtf8,
  NodeAlgorithmSuite
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
  class TestKeyring extends KeyringNode {
    async _onEncrypt(material: NodeEncryptionMaterial) {
      const unencryptedDataKey = new Uint8Array(
        material.suite.keyLengthBytes
      ).fill(0)
      const trace = {
        keyNamespace: 'k',
        keyName: 'k',
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
      }
      return material
        .setUnencryptedDataKey(unencryptedDataKey, trace)
        .addEncryptedDataKey(
          edk,
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
        )
    }
    async _onDecrypt(): Promise<NodeDecryptionMaterial> {
      throw new Error('I should never see this error')
    }
  }

  const keyRing = new TestKeyring()

  it('encrypt a string', async () => {
    const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16

    const plaintext = 'asdf'
    const { result, messageHeader } = await encrypt(keyRing, plaintext, {
      suiteId,
    })

    expect(messageHeader.suiteId).to.equal(suiteId)
    expect(messageHeader.encryptionContext).to.deep.equal({})
    expect(messageHeader.encryptedDataKeys).lengthOf(1)
    expect(messageHeader.encryptedDataKeys[0]).to.deep.equal(edk)

    const messageInfo = deserializeMessageHeader(result)
    if (!messageInfo) throw new Error('I should never see this error')

    expect(messageHeader).to.deep.equal(messageInfo.messageHeader)
  })

  it('encrypt a buffer', async () => {
    const encryptionContext = { simple: 'context' }

    const plaintext = Buffer.from('asdf')
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

  it('encrypt a stream', async () => {
    const encryptionContext = { simple: 'context' }

    let pushed = false
    const plaintext = from(
      (_: number, next: (err: Error | null, chunk: string | null) => void) => {
        if (pushed) return next(null, null)
        pushed = true
        next(null, 'asdf')
      }
    )

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

  it('Unsupported plaintext', async () => {
    const plaintext = {} as any
    await expect(encrypt(keyRing, plaintext)).to.rejectedWith(Error)
  })

  it('encryptStream', async () => {
    const encryptionContext = { simple: 'context' }

    const data = randomBytes(300)
    const i = data.values()
    const plaintext = from(
      (
        _: number,
        next: (err: Error | null, chunk: Uint8Array | null) => void
      ) => {
        /* Pushing 1 byte at time is the most annoying thing.
         * This is done intentionally to hit _every_ boundary condition.
         */
        const { value, done } = i.next()
        if (done) return next(null, null)
        next(null, new Uint8Array([value]))
      }
    )

    let messageHeader: any
    const buffer: Buffer[] = []
    const stream = plaintext
      .pipe(encryptStream(keyRing, { encryptionContext, frameLength: 5 }))
      .on('MessageHeader', (header: MessageHeader) => {
        // MessageHeader should only be called once
        if (messageHeader) throw new Error('I should never see this error')
        messageHeader = header
      })
      // data event to drain the stream
      .on('data', (chunk: Buffer) => {
        buffer.push(chunk)
      })

    await finishedAsync(stream)

    if (!messageHeader) throw new Error('I should never see this error')

    const result = Buffer.concat(buffer)

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

  it('Precondition: encryptStream needs a valid commitmentPolicy.', async () => {
    await expect(
      _encrypt(
        {
          commitmentPolicy: 'fake_policy' as any,
          maxEncryptedDataKeys: false,
        },
        keyRing,
        'asdf'
      )
    ).to.rejectedWith(Error, 'Invalid commitment policy.')
  })

  it('Precondition: encryptStream needs a valid maxEncryptedDataKeys.', async () => {
    await expect(
      _encrypt(
        {
          commitmentPolicy: CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
          maxEncryptedDataKeys: 0,
        },
        keyRing,
        'asdf'
      )
    ).to.rejectedWith(Error, 'Invalid maxEncryptedDataKeys value.')
  })

  it('Precondition: The frameLength must be less than the maximum frame size Node.js stream.', async () => {
    const frameLength = 0
    await expect(encrypt(keyRing, 'asdf', { frameLength })).to.rejectedWith(
      Error,
      'frameLength out of bounds: 0'
    )
  })

  it('Precondition: Only request NodeEncryptionMaterial for algorithm suites supported in commitmentPolicy.', async () => {
    await expect(
      _encrypt(
        {
          commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
          maxEncryptedDataKeys: false,
        },
        keyRing,
        'asdf',
        {
          suiteId:
            AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
        }
      )
    ).to.rejectedWith(
      Error,
      'Configuration conflict. Cannot encrypt due to CommitmentPolicy'
    )
  })

  it('Precondition: Only use NodeEncryptionMaterial for algorithm suites supported in commitmentPolicy.', async () => {
    let called_getEncryptionMaterials = false
    const cmm = {
      async getEncryptionMaterials() {
        called_getEncryptionMaterials = true
        return new NodeEncryptionMaterial(
          new NodeAlgorithmSuite(
            AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
          ),
          {}
        )
      },
    } as any
    await expect(
      _encrypt(
        {
          commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
          maxEncryptedDataKeys: false,
        },
        cmm,
        'asdf'
      )
    ).to.rejectedWith(
      Error,
      'Configuration conflict. Cannot encrypt due to CommitmentPolicy'
    )
    expect(called_getEncryptionMaterials).to.equal(true)
  })

  it('Precondition: _encryptStream encryption materials must not exceed maxEncryptedDataKeys', async () => {
    for (const numKeys of [2, 3, 4]) {
      let called_getEncryptionMaterials = false
      const cmm = {
        async getEncryptionMaterials() {
          called_getEncryptionMaterials = true
          const material = await keyRing.onEncrypt(
            new NodeEncryptionMaterial(
              new NodeAlgorithmSuite(
                AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
              ),
              {}
            )
          )
          for (let i = 1; i < numKeys; i++) {
            material.addEncryptedDataKey(
              edk,
              KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
            )
          }
          return material
        },
      } as any

      const encryptPromise = _encrypt(
        {
          commitmentPolicy: CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
          maxEncryptedDataKeys: 3,
        },
        cmm,
        'asdf'
      )

      if (numKeys > 3) {
        await expect(encryptPromise).to.rejectedWith(
          Error,
          'maxEncryptedDataKeys exceeded.'
        )
      } else {
        await encryptPromise
      }

      expect(called_getEncryptionMaterials).to.equal(true)
    }
  })

  it('can fully parse a framed message', async () => {
    const plaintext = 'asdf'
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
    for (; i < 5; i++) {
      bodyHeader = decodeBodyHeader(result, headerInfo, readPos)
      if (!bodyHeader) throw new Error('this should never happen')
      readPos = bodyHeader.readPos + bodyHeader.contentLength + tagLength
    }

    expect(i).to.equal(5) // 4 frames
    expect(bodyHeader.isFinalFrame).to.equal(true) // we got to the end

    // This implicitly tests that I have consumed all the data,
    // because otherwise the footer section will be too large
    const footerSection = result.slice(readPos)
    // This will throw if it does not deserialize correctly
    deserializeSignature(footerSection)
  })
})

async function finishedAsync(stream: any) {
  return new Promise<void>((resolve, reject) => {
    finished(stream, (err: Error) => (err ? reject(err) : resolve()))
  })
}
