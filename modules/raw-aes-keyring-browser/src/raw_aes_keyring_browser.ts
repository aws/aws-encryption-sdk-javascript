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
  WebCryptoDecryptionMaterial,
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  WebCryptoAlgorithmSuite,
  EncryptionContext, // eslint-disable-line no-unused-vars
  WrappingSuiteIdentifier, // eslint-disable-line no-unused-vars
  RawAesWrappingSuiteIdentifier,
  getSubtleFunction,
  _importCryptoKey,
  importCryptoKey
} from '@aws-crypto/material-management-browser'
import {
  serializeFactory,
  rawAesEncryptedDataKeyFactory,
  rawAesEncryptedPartsFactory,
  concatBuffers
} from '@aws-crypto/serialize'
import {
  _onEncrypt,
  _onDecrypt,
  WrapKey, // eslint-disable-line no-unused-vars
  UnwrapKey // eslint-disable-line no-unused-vars
} from '@aws-crypto/raw-keyring'
import { fromUtf8, toUtf8 } from '@aws-sdk/util-utf8-browser'
import { randomValuesOnly } from '@aws-crypto/random-source-browser'
import { getWebCryptoBackend, getZeroByteSubtle } from '@aws-crypto/web-crypto-backend'
const { encodeEncryptionContext } = serializeFactory(fromUtf8)
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
    needs(RawAesWrappingSuiteIdentifier[wrappingSuite], 'wrappingSuite not supported.')
    const suite = new WebCryptoAlgorithmSuite(wrappingSuite)
    const trace = { keyNamespace, keyName, flags: decryptFlags }
    const wrappingMaterial = new WebCryptoDecryptionMaterial(suite)
      /* Precondition: unencryptedMasterKey must correspond to the algorithm suite specification. */
      .setCryptoKey(masterKey, trace)

    const _wrapKey = async (material: WebCryptoEncryptionMaterial, context?: EncryptionContext) => {
      const aad = concatBuffers(...encodeEncryptionContext(context || {}))
      const { keyNamespace, keyName } = this

      return aesWrapKey(keyNamespace, keyName, material, aad, wrappingMaterial)
    }

    const _unwrapKey = async (material: WebCryptoDecryptionMaterial, edk: EncryptedDataKey, context?: EncryptionContext) => {
      const aad = concatBuffers(...encodeEncryptionContext(context || {}))
      const { keyNamespace, keyName } = this

      return aesUnwrapKey(keyNamespace, keyName, material, wrappingMaterial, edk, aad)
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

  _onEncrypt = _onEncrypt<WebCryptoAlgorithmSuite, RawAesKeyringWebCrypto>(randomValuesOnly)
  _onDecrypt = _onDecrypt<WebCryptoAlgorithmSuite, RawAesKeyringWebCrypto>()

  static importCryptoKey (masterKey: Uint8Array, wrappingSuite: WrappingSuiteIdentifier) {
    needs(masterKey instanceof Uint8Array, '')
    const suite = new WebCryptoAlgorithmSuite(wrappingSuite)
    const material = new WebCryptoDecryptionMaterial(suite)
    const trace = { keyNamespace: '', keyName: '', flags: decryptFlags }
    /* Precondition: masterKey must correspond to the algorithm suite specification. */
    material.setUnencryptedDataKey(masterKey, trace)
    return getWebCryptoBackend()
      .then(getZeroByteSubtle)
      .then(backend => _importCryptoKey(backend, material, ['encrypt', 'decrypt']))
  }
}
immutableClass(RawAesKeyringWebCrypto)

async function aesWrapKey(
  keyNamespace: string,
  keyName: string,
  material: WebCryptoEncryptionMaterial,
  aad: Uint8Array,
  wrappingMaterial: WebCryptoDecryptionMaterial
) {
  const backend = await getWebCryptoBackend()
  const iv = await backend.randomValues(material.suite.ivLength)

  const kdfGetSubtleEncrypt = getSubtleFunction(wrappingMaterial, backend, 'encrypt')
  const info = new Uint8Array()
  const dataKey = material.getUnencryptedDataKey()
  const buffer = await kdfGetSubtleEncrypt(info)(iv, aad)(dataKey)

  const edk = rawAesEncryptedDataKey(keyNamespace, keyName, iv, new Uint8Array(buffer), new Uint8Array())
  return material.addEncryptedDataKey(edk, encryptFlags)
}

async function aesUnwrapKey (
  keyNamespace: string,
  keyName: string,
  material: WebCryptoDecryptionMaterial,
  wrappingMaterial: WebCryptoDecryptionMaterial,
  edk: EncryptedDataKey,
  aad: Uint8Array
) {
  const { suite } = material
  const { iv, ciphertext, authTag } = rawAesEncryptedParts(suite, keyName, edk)

  const backend = await getWebCryptoBackend()

  const KdfGetSubtleDecrypt = getSubtleFunction(wrappingMaterial, backend, 'decrypt')
  const info = new Uint8Array()
  const buffer = await KdfGetSubtleDecrypt(info)(iv, aad)(concatBuffers(ciphertext, authTag))
  const trace = { keyNamespace, keyName, flags: decryptFlags }
  material.setUnencryptedDataKey(new Uint8Array(buffer), trace)
  const cryptoKey = await importCryptoKey(backend, material)
  return material
    .zeroUnencryptedDataKey()
    .setCryptoKey(cryptoKey, trace)
}
