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

import {
  KeyringNode,
  needs,
  NodeEncryptionMaterial, // eslint-disable-line no-unused-vars
  NodeDecryptionMaterial, // eslint-disable-line no-unused-vars
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  NodeAlgorithmSuite, // eslint-disable-line no-unused-vars
  EncryptionContext // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto'
import {
  serializeFactory,
  concatBuffers
} from '@aws-crypto/serialize'
import {
  _onEncrypt,
  _onDecrypt,
  NodeRawAesMaterial,
  rawAesEncryptedDataKeyFactory,
  rawAesEncryptedPartsFactory,
  WrappingSuiteIdentifier, // eslint-disable-line no-unused-vars
  WrapKey, // eslint-disable-line no-unused-vars
  UnwrapKey // eslint-disable-line no-unused-vars
} from '@aws-crypto/raw-keyring'
const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const toUtf8 = (input: Uint8Array) => Buffer
  .from(input.buffer, input.byteOffset, input.byteLength)
  .toString('utf8')
const { encodeEncryptionContext } = serializeFactory(fromUtf8)
const { rawAesEncryptedDataKey } = rawAesEncryptedDataKeyFactory(toUtf8, fromUtf8)
const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)

export type RawAesKeyringNodeInput = {
  keyNamespace: string
  keyName: string
  unencryptedMasterKey: Uint8Array,
  wrappingSuite: WrappingSuiteIdentifier
}

export class RawAesKeyringNode extends KeyringNode {
  public keyNamespace!: string
  public keyName!: string
  _wrapKey!: WrapKey<NodeAlgorithmSuite>
  _unwrapKey!: UnwrapKey<NodeAlgorithmSuite>

  constructor (input: RawAesKeyringNodeInput) {
    super()

    const { keyName, keyNamespace, unencryptedMasterKey, wrappingSuite } = input
    /* Precondition: AesKeyringNode needs identifying information for encrypt and decrypt. */
    needs(keyName && keyNamespace, 'Identifying information must be defined.')
    /* Precondition: wrappingSuite must be a valid RawAesWrappingSuite. */
    const wrappingMaterial = new NodeRawAesMaterial(wrappingSuite)
      /* Precondition: unencryptedMasterKey must correspond to the algorithm suite specification. */
      .setUnencryptedDataKey(unencryptedMasterKey, { keyNamespace, keyName, flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY })

    const _wrapKey = async (material: NodeEncryptionMaterial, context?: EncryptionContext) => {
      const aad = Buffer.concat(encodeEncryptionContext(context || {}))
      const { keyNamespace, keyName } = this

      return aesGcmWrapKey(keyNamespace, keyName, material, aad, wrappingMaterial)
    }

    const _unwrapKey = async (material: NodeDecryptionMaterial, edk: EncryptedDataKey, context?: EncryptionContext) => {
      const { keyNamespace, keyName } = this
      const aad = Buffer.concat(encodeEncryptionContext(context || {}))

      return aesGcmUnwrapKey(keyNamespace, keyName, material, wrappingMaterial, edk, aad)
    }

    readOnlyProperty(this, 'keyName', keyName)
    readOnlyProperty(this, 'keyNamespace', keyNamespace)
    readOnlyProperty(this, '_wrapKey', _wrapKey)
    readOnlyProperty(this, '_unwrapKey', _unwrapKey)
  }

  _filter ({ providerId, providerInfo }: EncryptedDataKey) {
    const { keyNamespace, keyName } = this
    return providerId === keyNamespace && providerInfo.startsWith(keyName)
  }

  _onEncrypt = _onEncrypt<NodeAlgorithmSuite, RawAesKeyringNode>(randomBytesAsync)
  _onDecrypt = _onDecrypt<NodeAlgorithmSuite, RawAesKeyringNode>()
}
immutableClass(RawAesKeyringNode)

const encryptFlags = KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
const decryptFlags = KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX

function aesGcmWrapKey (
  keyNamespace: string,
  keyName: string,
  material: NodeEncryptionMaterial,
  aad: Buffer,
  wrappingMaterial: NodeRawAesMaterial
): NodeEncryptionMaterial {
  const { encryption, ivLength } = wrappingMaterial.suite
  const iv = randomBytes(ivLength)

  const wrappingDataKey = wrappingMaterial.getUnencryptedDataKey()
  const dataKey = material.getUnencryptedDataKey()

  const cipher = createCipheriv(encryption, wrappingDataKey, iv)
    .setAAD(aad)
  // Buffer.concat will use the shared buffer space, and the resultant buffer will have a byteOffset...
  const ciphertext = concatBuffers(cipher.update(dataKey), cipher.final())
  const authTag = cipher.getAuthTag()

  const edk = rawAesEncryptedDataKey(
    keyNamespace,
    keyName,
    iv,
    ciphertext,
    authTag
  )

  return material.addEncryptedDataKey(edk, encryptFlags)
}

/**
 *
 * @param keyNamespace The keyring namespace (for KeyringTrace)
 * @param keyName The keyring name (for KeyringTrace and to extract the extra info stored in providerInfo)
 * @param material The target material to which the decrypted data key will be added
 * @param wrappingMaterial The material used to decrypt the EncryptedDataKey
 * @param edk The EncryptedDataKey on which to operate
 * @param aad The serialized aad (EncryptionContext)
 */
function aesGcmUnwrapKey (
  keyNamespace: string,
  keyName: string,
  material: NodeDecryptionMaterial,
  wrappingMaterial: NodeRawAesMaterial,
  edk: EncryptedDataKey,
  aad: Buffer
): NodeDecryptionMaterial {
  const { authTag, ciphertext, iv } = rawAesEncryptedParts(material.suite, keyName, edk)
  const { encryption } = wrappingMaterial.suite

  const decipher = createDecipheriv(encryption, wrappingMaterial.getUnencryptedDataKey(), iv)
    .setAAD(aad)
    .setAuthTag(authTag)
  // Buffer.concat will use the shared buffer space, and the resultant buffer will have a byteOffset...
  const unencryptedDataKey = concatBuffers(decipher.update(ciphertext), decipher.final())
  const trace = { keyNamespace, keyName, flags: decryptFlags }
  return material.setUnencryptedDataKey(unencryptedDataKey, trace)
}

function randomBytesAsync (size: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    randomBytes(size, (err: Error|null, buffer: Buffer) => {
      if (err) return reject(err)
      resolve(buffer)
    })
  })
}
