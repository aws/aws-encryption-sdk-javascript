// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KeyringWebCrypto,
  needs,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  EncryptedDataKey,
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  WebCryptoAlgorithmSuite,
  currySubtleFunction,
  _importCryptoKey,
  unwrapDataKey,
  importForWebCryptoEncryptionMaterial,
  importForWebCryptoDecryptionMaterial,
  AwsEsdkJsCryptoKey,
} from '@aws-crypto/material-management-browser'
import { serializeFactory, concatBuffers } from '@aws-crypto/serialize'
import {
  _onEncrypt,
  _onDecrypt,
  WebCryptoRawAesMaterial,
  rawAesEncryptedDataKeyFactory,
  rawAesEncryptedPartsFactory,
  WrappingSuiteIdentifier,
  WrapKey,
  UnwrapKey,
} from '@aws-crypto/raw-keyring'
import { fromUtf8, toUtf8 } from '@aws-sdk/util-utf8-browser'
import { randomValuesOnly } from '@aws-crypto/random-source-browser'
import {
  getWebCryptoBackend,
  getNonZeroByteBackend,
} from '@aws-crypto/web-crypto-backend'
const { serializeEncryptionContext } = serializeFactory(fromUtf8)
const { rawAesEncryptedDataKey } = rawAesEncryptedDataKeyFactory(
  toUtf8,
  fromUtf8
)
const { rawAesEncryptedParts } = rawAesEncryptedPartsFactory(fromUtf8)
const encryptFlags =
  KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY |
  KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
const decryptFlags =
  KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY |
  KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX

export type RawAesKeyringWebCryptoInput = {
  keyNamespace: string
  keyName: string
  masterKey: AwsEsdkJsCryptoKey
  wrappingSuite: WrappingSuiteIdentifier
}

export class RawAesKeyringWebCrypto extends KeyringWebCrypto {
  public declare keyNamespace: string
  public declare keyName: string
  declare _wrapKey: WrapKey<WebCryptoAlgorithmSuite>
  declare _unwrapKey: UnwrapKey<WebCryptoAlgorithmSuite>

  constructor(input: RawAesKeyringWebCryptoInput) {
    super()
    const { keyName, keyNamespace, masterKey, wrappingSuite } = input
    /* Precondition: AesKeyringWebCrypto needs identifying information for encrypt and decrypt. */
    needs(keyName && keyNamespace, 'Identifying information must be defined.')
    /* Precondition: RawAesKeyringWebCrypto requires a wrappingSuite to be a valid RawAesWrappingSuite. */
    const wrappingMaterial = new WebCryptoRawAesMaterial(wrappingSuite)
      /* Precondition: unencryptedMasterKey must correspond to the WebCryptoAlgorithmSuite specification.
       * Note: the KeyringTrace and flag are _only_ set because I am reusing an existing implementation.
       * See: raw_aes_material.ts in @aws-crypto/raw-keyring for details
       */
      .setCryptoKey(masterKey, {
        keyNamespace,
        keyName,
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
      })

    const _wrapKey = async (material: WebCryptoEncryptionMaterial) => {
      /* The AAD section is uInt16BE(length) + AAD
       * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
       * However, the RAW Keyring wants _only_ the ADD.
       * So, I just slice off the length.
       */
      const aad = serializeEncryptionContext(material.encryptionContext).slice(
        2
      )
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
      material: WebCryptoDecryptionMaterial,
      edk: EncryptedDataKey
    ) => {
      /* The AAD section is uInt16BE(length) + AAD
       * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
       * However, the RAW Keyring wants _only_ the ADD.
       * So, I just slice off the length.
       */
      const aad = serializeEncryptionContext(material.encryptionContext).slice(
        2
      )
      const { keyNamespace, keyName } = this

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

  _rawOnEncrypt = _onEncrypt<WebCryptoAlgorithmSuite, RawAesKeyringWebCrypto>(
    randomValuesOnly
  )
  _onEncrypt = async (material: WebCryptoEncryptionMaterial) => {
    const _material = await this._rawOnEncrypt(material)
    return importForWebCryptoEncryptionMaterial(_material)
  }

  /* onDecrypt does not need to import the crypto key, because this is handled in the unwrap operation
   * Encrypt needs to have access to the unencrypted data key to encrypt with other keyrings
   * but once I have functional material no other decrypt operations need to be performed.
   */
  _onDecrypt = _onDecrypt<WebCryptoAlgorithmSuite, RawAesKeyringWebCrypto>()

  static async importCryptoKey(
    masterKey: Uint8Array,
    wrappingSuite: WrappingSuiteIdentifier
  ): Promise<AwsEsdkJsCryptoKey> {
    needs(masterKey instanceof Uint8Array, 'Unsupported master key type.')
    const material = new WebCryptoRawAesMaterial(wrappingSuite)
      /* Precondition: masterKey must correspond to the algorithm suite specification.
       * Note: the KeyringTrace and flag are _only_ set because I am reusing an existing implementation.
       * See: raw_aes_material.ts in @aws-crypto/raw-keyring for details
       */
      .setUnencryptedDataKey(masterKey, {
        keyNamespace: 'importOnly',
        keyName: 'importOnly',
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
      })
    return backendForRawAesMasterKey().then(async (backend) =>
      _importCryptoKey(backend.subtle, material, ['encrypt', 'decrypt'])
    )
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
async function aesGcmWrapKey(
  keyNamespace: string,
  keyName: string,
  material: WebCryptoEncryptionMaterial,
  aad: Uint8Array,
  wrappingMaterial: WebCryptoRawAesMaterial
): Promise<WebCryptoEncryptionMaterial> {
  const backend = await backendForRawAesMasterKey()
  const iv = await backend.randomValues(material.suite.ivLength)

  const getSubtleInfo = currySubtleFunction(
    wrappingMaterial,
    backend,
    'encrypt'
  )
  const info = new Uint8Array()
  const { getSubtleEncrypt } = await getSubtleInfo(info)

  const dataKey = unwrapDataKey(material.getUnencryptedDataKey())
  const buffer = await getSubtleEncrypt(iv, aad)(dataKey)
  const ciphertext = new Uint8Array(
    buffer,
    0,
    buffer.byteLength - material.suite.tagLength / 8
  )
  const authTag = new Uint8Array(
    buffer,
    buffer.byteLength - material.suite.tagLength / 8
  )

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
async function aesGcmUnwrapKey(
  keyNamespace: string,
  keyName: string,
  material: WebCryptoDecryptionMaterial,
  wrappingMaterial: WebCryptoRawAesMaterial,
  edk: EncryptedDataKey,
  aad: Uint8Array
): Promise<WebCryptoDecryptionMaterial> {
  const { suite } = material
  const { iv, ciphertext, authTag } = rawAesEncryptedParts(suite, keyName, edk)

  const backend = await backendForRawAesMasterKey()

  const getSubtleInfo = currySubtleFunction(
    wrappingMaterial,
    backend,
    'decrypt'
  )
  const info = new Uint8Array()
  const getSubtleDecrypt = await getSubtleInfo(info)
  const buffer = await getSubtleDecrypt(
    iv,
    aad
  )(concatBuffers(ciphertext, authTag))
  const trace = { keyNamespace, keyName, flags: decryptFlags }
  material.setUnencryptedDataKey(new Uint8Array(buffer), trace)
  return importForWebCryptoDecryptionMaterial(material)
}

/**
 * The master key can not be zero length.
 * If the back end is mixed,
 * to support both zero and non-zero byte AES-GCM operations,
 * then the `NonZeroByteBackend` should be the native implementation.
 * I assert that it should be slightly harder to exfiltrate
 * from the native implementation than a JS implementation.
 * So I *force* the master key to be stored in the native implementation **only**.
 */
async function backendForRawAesMasterKey() {
  const backend = await getWebCryptoBackend()
  const { randomValues } = backend
  const subtle = getNonZeroByteBackend(backend)

  return { randomValues, subtle }
}
