// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KeyringNode,
  needs,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  EncryptedDataKey,
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  unwrapDataKey,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto'
import { serializeFactory, concatBuffers } from '@aws-crypto/serialize'
import {
  _onEncrypt,
  _onDecrypt,
  NodeRawAesMaterial,
  rawAesEncryptedDataKeyFactory,
  rawAesEncryptedPartsFactory,
  WrappingSuiteIdentifier,
  WrapKey,
  UnwrapKey,
} from '@aws-crypto/raw-keyring'
const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const toUtf8 = (input: Uint8Array) =>
  Buffer.from(input.buffer, input.byteOffset, input.byteLength).toString('utf8')
const { serializeEncryptionContext } = serializeFactory(fromUtf8)
const { rawAesEncryptedDataKey } = rawAesEncryptedDataKeyFactory(
  toUtf8,
  fromUtf8
)
const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)

export type RawAesKeyringNodeInput = {
  keyNamespace: string
  keyName: string
  unencryptedMasterKey: Uint8Array
  wrappingSuite: WrappingSuiteIdentifier
}

export class RawAesKeyringNode extends KeyringNode {
  public declare keyNamespace: string
  public declare keyName: string
  declare _wrapKey: WrapKey<NodeAlgorithmSuite>
  declare _unwrapKey: UnwrapKey<NodeAlgorithmSuite>

  constructor(input: RawAesKeyringNodeInput) {
    super()

    const { keyName, keyNamespace, unencryptedMasterKey, wrappingSuite } = input
    /* Precondition: AesKeyringNode needs identifying information for encrypt and decrypt. */
    needs(keyName && keyNamespace, 'Identifying information must be defined.')
    /* Precondition: RawAesKeyringNode requires wrappingSuite to be a valid RawAesWrappingSuite. */
    const wrappingMaterial = new NodeRawAesMaterial(wrappingSuite)
      /* Precondition: unencryptedMasterKey must correspond to the NodeAlgorithmSuite specification.
       * Note: the KeyringTrace and flag are _only_ set because I am reusing an existing implementation.
       * See: raw_aes_material.ts in @aws-crypto/raw-keyring for details
       */
      .setUnencryptedDataKey(unencryptedMasterKey, {
        keyNamespace,
        keyName,
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
      })

    const _wrapKey = async (material: NodeEncryptionMaterial) => {
      /* The AAD section is uInt16BE(length) + AAD
       * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
       * However, the RAW Keyring wants _only_ the ADD.
       * So, I just slice off the length.
       */
      const { buffer, byteOffset, byteLength } = serializeEncryptionContext(
        material.encryptionContext
      ).slice(2)
      const aad = Buffer.from(buffer, byteOffset, byteLength)
      const { keyNamespace, keyName } = this

      return aesGcmWrapKey(
        keyNamespace,
        keyName,
        material,
        aad,
        wrappingMaterial
      )
    }

    const _unwrapKey = async (
      material: NodeDecryptionMaterial,
      edk: EncryptedDataKey
    ) => {
      const { keyNamespace, keyName } = this
      /* The AAD section is uInt16BE(length) + AAD
       * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
       * However, the RAW Keyring wants _only_ the ADD.
       * So, I just slice off the length.
       */
      const { buffer, byteOffset, byteLength } = serializeEncryptionContext(
        material.encryptionContext
      ).slice(2)
      const aad = Buffer.from(buffer, byteOffset, byteLength)
      // const aad = Buffer.concat(encodeEncryptionContext(context || {}))

      return aesGcmUnwrapKey(
        keyNamespace,
        keyName,
        material,
        wrappingMaterial,
        edk,
        aad
      )
    }

    readOnlyProperty(this, 'keyName', keyName)
    readOnlyProperty(this, 'keyNamespace', keyNamespace)
    readOnlyProperty(this, '_wrapKey', _wrapKey)
    readOnlyProperty(this, '_unwrapKey', _unwrapKey)
  }

  _filter({ providerId, providerInfo }: EncryptedDataKey) {
    const { keyNamespace, keyName } = this
    return providerId === keyNamespace && providerInfo.startsWith(keyName)
  }

  _onEncrypt = _onEncrypt<NodeAlgorithmSuite, RawAesKeyringNode>(
    randomBytesAsync
  )
  _onDecrypt = _onDecrypt<NodeAlgorithmSuite, RawAesKeyringNode>()
}
immutableClass(RawAesKeyringNode)

const encryptFlags =
  KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY |
  KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
const decryptFlags =
  KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY |
  KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX

/**
 * Uses aes-gcm to encrypt the data key and return the passed NodeEncryptionMaterial with
 * an EncryptedDataKey added.
 * @param keyNamespace [String] The keyring namespace (for KeyringTrace)
 * @param keyName [String] The keyring name (for KeyringTrace and to extract the extra info stored in providerInfo)
 * @param material [NodeEncryptionMaterial] The target material to which the EncryptedDataKey will be added
 * @param aad [Buffer] The serialized aad (EncryptionContext)
 * @param wrappingMaterial [NodeRawAesMaterial] The material used to decrypt the EncryptedDataKey
 * @returns [NodeEncryptionMaterial] Mutates and returns the same NodeEncryptionMaterial that was passed but with an EncryptedDataKey added
 */
function aesGcmWrapKey(
  keyNamespace: string,
  keyName: string,
  material: NodeEncryptionMaterial,
  aad: Buffer,
  wrappingMaterial: NodeRawAesMaterial
): NodeEncryptionMaterial {
  const { encryption, ivLength } = wrappingMaterial.suite
  const iv = randomBytes(ivLength)

  const wrappingDataKey = wrappingMaterial.getUnencryptedDataKey()
  const dataKey = unwrapDataKey(material.getUnencryptedDataKey())

  const cipher = createCipheriv(encryption, wrappingDataKey, iv).setAAD(aad)
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
 * Uses aes-gcm to decrypt the encrypted data key and return the passed NodeDecryptionMaterial with
 * the unencrypted data key set.
 * @param keyNamespace [String] The keyring namespace (for KeyringTrace)
 * @param keyName [String] The keyring name (for KeyringTrace and to extract the extra info stored in providerInfo)
 * @param material [NodeDecryptionMaterial] The target material to which the decrypted data key will be added
 * @param wrappingMaterial [NodeRawAesMaterial] The material used to decrypt the EncryptedDataKey
 * @param edk [EncryptedDataKey] The EncryptedDataKey on which to operate
 * @param aad [Buffer] The serialized aad (EncryptionContext)
 * @returns [NodeDecryptionMaterial] Mutates and returns the same NodeDecryptionMaterial that was passed but with the unencrypted data key set
 */
function aesGcmUnwrapKey(
  keyNamespace: string,
  keyName: string,
  material: NodeDecryptionMaterial,
  wrappingMaterial: NodeRawAesMaterial,
  edk: EncryptedDataKey,
  aad: Buffer
): NodeDecryptionMaterial {
  const { authTag, ciphertext, iv } = rawAesEncryptedParts(
    material.suite,
    keyName,
    edk
  )
  const { encryption } = wrappingMaterial.suite

  // createDecipheriv is incorrectly typed in @types/node. It should take key: CipherKey, not key: BinaryLike
  const decipher = createDecipheriv(
    encryption,
    wrappingMaterial.getUnencryptedDataKey() as any,
    iv
  )
    .setAAD(aad)
    .setAuthTag(authTag)
  // Buffer.concat will use the shared buffer space, and the resultant buffer will have a byteOffset...
  const unencryptedDataKey = concatBuffers(
    decipher.update(ciphertext),
    decipher.final()
  )
  const trace = { keyNamespace, keyName, flags: decryptFlags }
  return material.setUnencryptedDataKey(unencryptedDataKey, trace)
}

async function randomBytesAsync(size: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    randomBytes(size, (err: Error | null, buffer: Buffer) => {
      if (err) return reject(err)
      resolve(buffer)
    })
  })
}
