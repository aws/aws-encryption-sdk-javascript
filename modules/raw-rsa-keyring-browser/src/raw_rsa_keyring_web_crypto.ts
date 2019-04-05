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
  EncryptedDataKey,
  KeyringTrace, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  bytes2JWK,
  keyUsageForMaterial,
  MixedBackendCryptoKey, // eslint-disable-line no-unused-vars
  WebCryptoAlgorithmSuite // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'

import {
  getWebCryptoBackend,
  getNonZeroByteBackend,
  isFullSupportWebCryptoBackend
} from '@aws-crypto/web-crypto-backend'
import {
  _onEncrypt,
  _onDecrypt,
  WrapKey, // eslint-disable-line no-unused-vars
  UnwrapKey // eslint-disable-line no-unused-vars
} from '@aws-crypto/raw-keyring'
import { randomValuesOnly } from '@aws-crypto/random-source-browser'
import { RawRsaKeyringWebCryptoInput, RsaImportableKey } from './types' // eslint-disable-line no-unused-vars
import { getImportOptions, getWrappingAlgorithm, flattenMixedCryptoKey } from './get_import_options'

export class RawRsaKeyringWebCrypto extends KeyringWebCrypto {
  public keyNamespace!: string
  public keyName!: string
  _wrapKey!: WrapKey<WebCryptoAlgorithmSuite>
  _unwrapKey!: UnwrapKey<WebCryptoAlgorithmSuite>

  constructor (input: RawRsaKeyringWebCryptoInput) {
    super()

    const { publicKey, privateKey, keyName, keyNamespace } = input
    /* Precondition: RsaKeyringWebCrypto needs either a public or a private key to operate. */
    needs(publicKey || privateKey, 'No Key provided.')
    /* Precondition: RsaKeyringWebCrypto needs identifying information for encrypt and decrypt. */
    needs(keyName && keyNamespace, 'Identifying information must be defined.')

    const wrappingAlgorithm = getWrappingAlgorithm(publicKey, privateKey)

    const _wrapKey = async (material: WebCryptoEncryptionMaterial) => {
      /* Precondition: I must have a publicKey to wrap. */
      if (!publicKey) throw new Error('No publicKey configured, encrypt no supported.')

      // The nonZero backend is used because some browsers support Subtle Crypto
      // but do not support Zero Byte AES-GCM. I want to use the native
      // browser implementation of wrapKey
      const subtle = getNonZeroByteBackend(await getWebCryptoBackend())
      // Can not use importCryptoKey as `wrapKey` requires extractable = true
      const extractable = true
      const { encryption } = material.suite
      const importFormat = 'jwk'
      const keyUsages = ['unwrapKey'] // limit the use of this key (*not* decrypt, encrypt, deriveKey)
      const jwk = bytes2JWK(material.getUnencryptedDataKey())
      const cryptoKey = await subtle.importKey(importFormat, jwk, encryption, extractable, keyUsages)

      const wrapFormat = 'raw'
      const encryptedArrayBuffer = await subtle.wrapKey(wrapFormat, cryptoKey, publicKey, wrappingAlgorithm)

      // Can the extractable setting of cryptoKey be changed to false here?  If so, do it.
      const edk = new EncryptedDataKey({
        providerId: keyNamespace,
        providerInfo: keyName,
        encryptedDataKey: new Uint8Array(encryptedArrayBuffer)
      })

      return material.addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    }

    /* returns either an array of 1 CryptoKey an array of both from MixedBackendCryptoKey e.g.
     * [privateKey] || [nonZeroByteCryptoKey, zeroByteCryptoKey]
     */
    const privateKeys = flattenMixedCryptoKey(privateKey)

    const _unwrapKey = async (material: WebCryptoDecryptionMaterial, edk: EncryptedDataKey) => {
      /* Precondition: I must have a privateKey to unwrap. */
      if (!privateKey) throw new Error('No privateKey configured, decrypt not supported.')
      const backend = await getWebCryptoBackend()
      const { suite } = material

      const trace: KeyringTrace = {
        keyName: this.keyName,
        keyNamespace: this.keyNamespace,
        flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
      }

      const format = 'raw'
      const extractable = false
      const algorithm = suite.kdf ? suite.kdf : suite.encryption
      const keyUsages = [keyUsageForMaterial(material)]

      const importArgs:Parameters<SubtleCrypto['unwrapKey']> = [
        format,
        edk.encryptedDataKey,
        privateKeys[0],
        wrappingAlgorithm,
        algorithm,
        extractable,
        keyUsages
      ]

      if (isFullSupportWebCryptoBackend(backend)) {
        const cryptoKey = await backend.subtle.unwrapKey(...importArgs)
        return material.setCryptoKey(cryptoKey, trace)
      } else {
        const importZeroBackend = <Parameters<SubtleCrypto['unwrapKey']>>[...importArgs]
        importZeroBackend[2] = privateKeys[1]
        const mixedDataKey: MixedBackendCryptoKey = await Promise.all([
          backend.nonZeroByteSubtle.unwrapKey(...importArgs),
          backend.zeroByteSubtle.unwrapKey(...importZeroBackend)
        ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({ nonZeroByteCryptoKey, zeroByteCryptoKey }))
        return material.setCryptoKey(mixedDataKey, trace)
      }
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

  _onEncrypt = _onEncrypt<WebCryptoAlgorithmSuite, RawRsaKeyringWebCrypto>(randomValuesOnly)
  _onDecrypt = _onDecrypt<WebCryptoAlgorithmSuite, RawRsaKeyringWebCrypto>()

  static async importPublicKey (publicKey: RsaImportableKey): Promise<CryptoKey> {
    const { wrappingAlgorithm, format, key } = getImportOptions(publicKey)
    const backend = await getWebCryptoBackend()
    const subtle = getNonZeroByteBackend(backend)
    return subtle.importKey(format, key, wrappingAlgorithm, false, ['wrapKey'])
  }

  static async importPrivateKey (privateKey: RsaImportableKey): Promise<CryptoKey|MixedBackendCryptoKey> {
    const { wrappingAlgorithm, format, key } = getImportOptions(privateKey)
    const backend = await getWebCryptoBackend()

    if (isFullSupportWebCryptoBackend(backend)) {
      return backend.subtle.importKey(format, key, wrappingAlgorithm, false, ['unwrapKey'])
    } else {
      return Promise.all([
        backend.nonZeroByteSubtle.importKey(format, key, wrappingAlgorithm, false, ['unwrapKey']),
        backend.zeroByteSubtle.importKey(format, key, wrappingAlgorithm, false, ['unwrapKey'])
      ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({ nonZeroByteCryptoKey, zeroByteCryptoKey }))
    }
  }
}
immutableClass(RawRsaKeyringWebCrypto)
