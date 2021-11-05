// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KeyringWebCrypto,
  needs,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  EncryptedDataKey,
  KeyringTrace,
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  bytes2JWK,
  keyUsageForMaterial,
  importForWebCryptoEncryptionMaterial,
  unwrapDataKey,
  MixedBackendCryptoKey,
  WebCryptoAlgorithmSuite,
  AwsEsdkJsCryptoKey,
} from '@aws-crypto/material-management-browser'

import {
  getWebCryptoBackend,
  getNonZeroByteBackend,
  isFullSupportWebCryptoBackend,
} from '@aws-crypto/web-crypto-backend'
import {
  _onEncrypt,
  _onDecrypt,
  WrapKey,
  UnwrapKey,
} from '@aws-crypto/raw-keyring'
import { randomValuesOnly } from '@aws-crypto/random-source-browser'
import { RawRsaKeyringWebCryptoInput, RsaImportableKey } from './types'
import {
  getImportOptions,
  getWrappingAlgorithm,
  flattenMixedCryptoKey,
} from './get_import_options'

// noinspection TypeScriptValidateTypes
export class RawRsaKeyringWebCrypto extends KeyringWebCrypto {
  public declare keyNamespace: string
  public declare keyName: string
  declare _wrapKey: WrapKey<WebCryptoAlgorithmSuite>
  declare _unwrapKey: UnwrapKey<WebCryptoAlgorithmSuite>

  constructor(input: RawRsaKeyringWebCryptoInput) {
    super()

    const { publicKey, privateKey, keyName, keyNamespace } = input
    /* Precondition: RsaKeyringWebCrypto needs either a public or a private key to operate. */
    needs(publicKey || privateKey, 'No Key provided.')
    /* Precondition: RsaKeyringWebCrypto needs identifying information for encrypt and decrypt. */
    needs(keyName && keyNamespace, 'Identifying information must be defined.')

    const wrappingAlgorithm = getWrappingAlgorithm(publicKey, privateKey)

    const _wrapKey = async (material: WebCryptoEncryptionMaterial) => {
      /* Precondition: I must have a publicKey to wrap. */
      if (!publicKey)
        throw new Error('No publicKey configured, encrypt not supported.')

      // The nonZero backend is used because some browsers support Subtle Crypto
      // but do not support Zero Byte AES-GCM. I want to use the native
      // browser implementation of wrapKey
      const subtle = getNonZeroByteBackend(await getWebCryptoBackend())
      /* Can not use importCryptoKey as `wrapKey` requires extractable = true
       * In web crypto `wrapKey` is a composition of `export` and `encrypt` and
       * so the cryptoKey must have `extractable = true`.
       */
      const extractable = true
      const { encryption } = material.suite
      const importFormat = 'jwk'
      const keyUsages: KeyUsage[] = ['wrapKey'] // limit the use of this key (*not* decrypt, encrypt, deriveKey)
      const jwk = bytes2JWK(unwrapDataKey(material.getUnencryptedDataKey()))
      const cryptoKey = await subtle.importKey(
        importFormat,
        jwk,
        encryption,
        extractable,
        keyUsages
      )

      const wrapFormat = 'raw'
      const encryptedArrayBuffer = await subtle.wrapKey(
        wrapFormat,
        cryptoKey,
        publicKey,
        wrappingAlgorithm
      )

      // Can the extractable setting of cryptoKey be changed to false here?  If so, do it.
      const edk = new EncryptedDataKey({
        providerId: keyNamespace,
        providerInfo: keyName,
        encryptedDataKey: new Uint8Array(encryptedArrayBuffer),
      })

      return material.addEncryptedDataKey(
        edk,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )
    }

    /* returns either an array of 1 CryptoKey or an array of both from MixedBackendCryptoKey e.g.
     * [privateKey] || [nonZeroByteCryptoKey, zeroByteCryptoKey]
     */
    const privateKeys = flattenMixedCryptoKey(privateKey)

    const _unwrapKey = async (
      material: WebCryptoDecryptionMaterial,
      edk: EncryptedDataKey
    ) => {
      /* Precondition: I must have a privateKey to unwrap. */
      if (!privateKey)
        throw new Error('No privateKey configured, decrypt not supported.')
      const backend = await getWebCryptoBackend()
      const { suite } = material

      const trace: KeyringTrace = {
        keyName: this.keyName,
        keyNamespace: this.keyNamespace,
        flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
      }

      const format = 'raw'
      const extractable = false
      const algorithm = suite.kdf ? suite.kdf : suite.encryption
      const keyUsages = [keyUsageForMaterial(material)]

      const importArgs: Parameters<SubtleCrypto['unwrapKey']> = [
        format,
        edk.encryptedDataKey,
        privateKeys[0],
        wrappingAlgorithm,
        algorithm,
        extractable,
        keyUsages,
      ]

      /* This is superior to importForWebCryptoDecryptionMaterial.
       * Here I use `subtle.unwrap` and bring the unencrypted data key into the WebCrypto world
       * without ever exposing the unencrypted data key to JavaScript.
       */
      if (isFullSupportWebCryptoBackend(backend)) {
        const cryptoKey = await backend.subtle.unwrapKey(...importArgs)
        return material.setCryptoKey(cryptoKey, trace)
      } else {
        const importZeroBackend = [...importArgs] as Parameters<
          SubtleCrypto['unwrapKey']
        >
        importZeroBackend[2] = privateKeys[1]
        const mixedDataKey: MixedBackendCryptoKey = await Promise.all([
          backend.nonZeroByteSubtle.unwrapKey(...importArgs),
          backend.zeroByteSubtle.unwrapKey(...importZeroBackend),
        ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({
          nonZeroByteCryptoKey,
          zeroByteCryptoKey,
        }))
        return material.setCryptoKey(mixedDataKey, trace)
      }
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

  _rawOnEncrypt = _onEncrypt<WebCryptoAlgorithmSuite, RawRsaKeyringWebCrypto>(
    randomValuesOnly
  )
  _onEncrypt = async (material: WebCryptoEncryptionMaterial) => {
    const _material = await this._rawOnEncrypt(material)
    return importForWebCryptoEncryptionMaterial(_material)
  }

  /* onDecrypt does not need to import the CryptoKey, because this is handled in the unwrap operation.
   * Encrypt needs to have access to the unencrypted data key to encrypt with other keyrings
   * but once I have functional material no other decrypt operations need to be performed.
   */
  _onDecrypt = _onDecrypt<WebCryptoAlgorithmSuite, RawRsaKeyringWebCrypto>()

  static async importPublicKey(
    publicKey: RsaImportableKey
  ): Promise<AwsEsdkJsCryptoKey> {
    const op = getImportOptions(publicKey)
    const backend = await getWebCryptoBackend()
    const subtle = getNonZeroByteBackend(backend)

    return ImportKeyTypeOverload(op, subtle, ['wrapKey'])
  }

  static async importPrivateKey(
    privateKey: RsaImportableKey
  ): Promise<AwsEsdkJsCryptoKey | MixedBackendCryptoKey> {
    const op = getImportOptions(privateKey)
    const backend = await getWebCryptoBackend()

    if (isFullSupportWebCryptoBackend(backend)) {
      return ImportKeyTypeOverload(op, backend.subtle, ['unwrapKey'])
    } else {
      return Promise.all([
        ImportKeyTypeOverload(op, backend.nonZeroByteSubtle, ['unwrapKey']),
        ImportKeyTypeOverload(op, backend.zeroByteSubtle, ['unwrapKey']),
      ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({
        nonZeroByteCryptoKey,
        zeroByteCryptoKey,
      }))
    }
  }
}
immutableClass(RawRsaKeyringWebCrypto)

// TS2769 Note:
// TS2769 is "No overload matches this call".
// Above and below, TS is incorrect.
// `importKey` has two overrides,
// They are abbreviated below:
// ```
// importKey(format: "jwk", keyData: JsonWebKey, algorithm: AlgorithmIdentifier | ... , extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
// importKey(format:  "raw" | "pkcs8" | "spki", keyData: BufferSource, algorithm: AlgorithmIdentifier | ..., extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
// ```
// The method getImportOptions explicitly
// returns format & key that match
// these overrides.
// However, TS is unable to recognize this easily.
// The following ugly function does the disambiguation.
// There are 2 problems that TS is having.
// First when format key and wrappingAlgorithm are independent,
// TS does not _remember_ the relationship between format and key.
// The second issue is related,
// when trying to select the proper overload,
// it is collapsing the definition of format.
// Thus discriminating the union by `format`
// helps TS understand all the arguments.
async function ImportKeyTypeOverload(
  op: ReturnType<typeof getImportOptions>,
  subtle: SubtleCrypto,
  keyUsages: KeyUsage[]
): Promise<AwsEsdkJsCryptoKey> {
  return op.format == 'jwk'
    ? subtle.importKey(
        op.format,
        op.key,
        op.wrappingAlgorithm,
        false,
        keyUsages
      )
    : subtle.importKey(
        op.format,
        op.key,
        op.wrappingAlgorithm,
        false,
        keyUsages
      )
}
