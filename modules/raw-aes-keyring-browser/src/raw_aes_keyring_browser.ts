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
  KeyringWebCrypto,
  needs,
  WebCryptoEncryptionMaterial, // eslint-disable-line no-unused-vars
  WebCryptoDecryptionMaterial, // eslint-disable-line no-unused-vars
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  WebCryptoAlgorithmSuite, // eslint-disable-line no-unused-vars
  EncryptionContext, // eslint-disable-line no-unused-vars
  getSubtleFunction,
  _importCryptoKey,
  importForWebCryptoEncryptionMaterial,
  importForWebCryptoDecryptionMaterial
} from '@aws-crypto/material-management-browser'
import {
  serializeFactory,
  concatBuffers
} from '@aws-crypto/serialize'
import {
  _onEncrypt,
  _onDecrypt,
  WebCryptoRawAesMaterial,
  rawAesEncryptedDataKeyFactory,
  rawAesEncryptedPartsFactory,
  WrappingSuiteIdentifier, // eslint-disable-line no-unused-vars
  WrapKey, // eslint-disable-line no-unused-vars
  UnwrapKey // eslint-disable-line no-unused-vars
} from '@aws-crypto/raw-keyring'
import { fromUtf8, toUtf8 } from '@aws-sdk/util-utf8-browser'
import { randomValuesOnly } from '@aws-crypto/random-source-browser'
import { getWebCryptoBackend, getZeroByteSubtle } from '@aws-crypto/web-crypto-backend'
const { serializeEncryptionContext } = serializeFactory(fromUtf8)
const { rawAesEncryptedDataKey } = rawAesEncryptedDataKeyFactory(toUtf8, fromUtf8)
const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)
const encryptFlags = KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
const decryptFlags = KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX

export type RawAesKeyringWebCryptoInput = {
  keyNamespace: string
  keyName: string
  masterKey: CryptoKey,
  wrappingSuite: WrappingSuiteIdentifier
}

export class RawAesKeyringWebCrypto extends KeyringWebCrypto {
  public keyNamespace!: string
  public keyName!: string
  _wrapKey!: WrapKey<WebCryptoAlgorithmSuite>
  _unwrapKey!: UnwrapKey<WebCryptoAlgorithmSuite>

  constructor (input: RawAesKeyringWebCryptoInput) {
    super()
    const { keyName, keyNamespace, masterKey, wrappingSuite } = input
    /* Precondition: AesKeyringWebCrypto needs identifying information for encrypt and decrypt. */
    needs(keyName && keyNamespace, 'Identifying information must be defined.')
    /* Precondition: wrappingSuite must be a valid RawAesWrappingSuite. */
    const wrappingMaterial = new WebCryptoRawAesMaterial(wrappingSuite)
      /* Precondition: unencryptedMasterKey must correspond to the algorithm suite specification.
       * Note: the KeyringTrace and flag are _only_ set because I am reusing an existing implementation.
       * See: raw_aes_material.ts in @aws-crypto/raw-keyring for details
       */
      .setCryptoKey(masterKey, { keyNamespace, keyName, flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY })

    const _wrapKey = async (material: WebCryptoEncryptionMaterial, context?: EncryptionContext) => {
      /* The AAD section is uInt16BE(length) + AAD
       * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
       * However, the RAW Keyring wants _only_ the ADD.
       * So, I just slice off the length.
       */
      const aad = serializeEncryptionContext(context || {}).slice(2)
      const { keyNamespace, keyName } = this

      return aesGcmWrapKey(keyNamespace, keyName, material, aad, wrappingMaterial)
    }

    const _unwrapKey = async (material: WebCryptoDecryptionMaterial, edk: EncryptedDataKey, context?: EncryptionContext) => {
      /* The AAD section is uInt16BE(length) + AAD
       * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
       * However, the RAW Keyring wants _only_ the ADD.
       * So, I just slice off the length.
       */
      const aad = serializeEncryptionContext(context || {}).slice(2)
      const { keyNamespace, keyName } = this

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

  _rawOnEncrypt = _onEncrypt<WebCryptoAlgorithmSuite, RawAesKeyringWebCrypto>(randomValuesOnly)
  _onEncrypt = async (material: WebCryptoEncryptionMaterial, context?: EncryptionContext) => {
    const _material = await this._rawOnEncrypt(material, context)
    return importForWebCryptoEncryptionMaterial(_material)
  }

  /* onDecrypt does not need to import the crypto key, because this is handled in the unwrap operation
   * Encrypt needs to have access to the unencrypted data key to encrypt with other keyrings
   * but once I have functional material no other decrypt operations need to be performed.
   */
  _onDecrypt = _onDecrypt<WebCryptoAlgorithmSuite, RawAesKeyringWebCrypto>()

  static async importCryptoKey (masterKey: Uint8Array, wrappingSuite: WrappingSuiteIdentifier) {
    needs(masterKey instanceof Uint8Array, 'Unsupported master key type.')
    const material = new WebCryptoRawAesMaterial(wrappingSuite)
      /* Precondition: masterKey must correspond to the algorithm suite specification.
      * Note: the KeyringTrace and flag are _only_ set because I am reusing an existing implementation.
      * See: raw_aes_material.ts in @aws-crypto/raw-keyring for details
      */
      .setUnencryptedDataKey(masterKey, { keyNamespace: 'importOnly', keyName: 'importOnly', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY })
    return getWebCryptoBackend()
      .then(getZeroByteSubtle)
      .then(backend => _importCryptoKey(backend, material, ['encrypt', 'decrypt']))
  }
}
immutableClass(RawAesKeyringWebCrypto)

/**
 * Uses aes-gcm to encrypt the data key and return the passed WebCryptoEncryptionMaterial with
 * an EncryptedDataKey added.
 * @param keyNamespace [String] The keyring namespace (for KeyringTrace)
 * @param keyName [String] The keyring name (for KeyringTrace and to extract the extra info stored in providerInfo)
 * @param material [WebCryptoEncryptionMaterial] The target material to which the EncryptedDataKey will be added
 * @param aad [Uint8Array] The serialized aad (EncryptionContext)
 * @param wrappingMaterial [WebCryptoRawAesMaterial] The material used to decrypt the EncryptedDataKey
 * @returns [WebCryptoEncryptionMaterial] Mutates and returns the same WebCryptoEncryptionMaterial that was passed but with an EncryptedDataKey added
 */
async function aesGcmWrapKey (
  keyNamespace: string,
  keyName: string,
  material: WebCryptoEncryptionMaterial,
  aad: Uint8Array,
  wrappingMaterial: WebCryptoRawAesMaterial
): Promise<WebCryptoEncryptionMaterial> {
  const backend = await getWebCryptoBackend()
  const iv = await backend.randomValues(material.suite.ivLength)

  const kdfGetSubtleEncrypt = getSubtleFunction(wrappingMaterial, backend, 'encrypt')
  const info = new Uint8Array()
  const dataKey = material.getUnencryptedDataKey()
  const buffer = await kdfGetSubtleEncrypt(info)(iv, aad)(dataKey)
  const ciphertext = new Uint8Array(buffer, 0, buffer.byteLength - material.suite.tagLength / 8)
  const authTag = new Uint8Array(buffer, buffer.byteLength - material.suite.tagLength / 8)

  const edk = rawAesEncryptedDataKey(keyNamespace, keyName, iv, ciphertext, authTag)
  return material.addEncryptedDataKey(edk, encryptFlags)
}

/**
 * Uses aes-gcm to decrypt the encrypted data key and return the passed WebCryptoDecryptionMaterial with
 * the unencrypted data key set.
 * @param keyNamespace [String] The keyring namespace (for KeyringTrace)
 * @param keyName [String] The keyring name (for KeyringTrace and to extract the extra info stored in providerInfo)
 * @param material [WebCryptoDecryptionMaterial] The target material to which the decrypted data key will be added
 * @param wrappingMaterial [WebCryptoRawAesMaterial] The material used to decrypt the EncryptedDataKey
 * @param edk [EncryptedDataKey] The EncryptedDataKey on which to operate
 * @param aad [Uint8Array] The serialized aad (EncryptionContext)
 * @returns [WebCryptoDecryptionMaterial] Mutates and returns the same WebCryptoDecryptionMaterial that was passed but with the unencrypted data key set
 */
async function aesGcmUnwrapKey (
  keyNamespace: string,
  keyName: string,
  material: WebCryptoDecryptionMaterial,
  wrappingMaterial: WebCryptoRawAesMaterial,
  edk: EncryptedDataKey,
  aad: Uint8Array
): Promise<WebCryptoDecryptionMaterial> {
  const { suite } = material
  const { iv, ciphertext, authTag } = rawAesEncryptedParts(suite, keyName, edk)

  const backend = await getWebCryptoBackend()

  const KdfGetSubtleDecrypt = getSubtleFunction(wrappingMaterial, backend, 'decrypt')
  const info = new Uint8Array()
  const buffer = await KdfGetSubtleDecrypt(info)(iv, aad)(concatBuffers(ciphertext, authTag))
  const trace = { keyNamespace, keyName, flags: decryptFlags }
  material.setUnencryptedDataKey(new Uint8Array(buffer), trace)
  return importForWebCryptoDecryptionMaterial(material)
}
