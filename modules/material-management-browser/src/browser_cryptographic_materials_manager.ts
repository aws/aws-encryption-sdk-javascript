// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  WebCryptoMaterialsManager,
  EncryptionRequest,
  DecryptionRequest,
  EncryptionContext,
  WebCryptoAlgorithmSuite,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  SignatureKey,
  needs,
  readOnlyProperty,
  VerificationKey,
  AlgorithmSuiteIdentifier,
  immutableBaseClass,
  KeyringWebCrypto,
  GetEncryptionMaterials,
  GetDecryptMaterials,
} from '@aws-crypto/material-management'

import { ENCODED_SIGNER_KEY } from '@aws-crypto/serialize'
import {
  getWebCryptoBackend,
  getNonZeroByteBackend,
} from '@aws-crypto/web-crypto-backend'
import { fromBase64, toBase64 } from '@aws-sdk/util-base64-browser'

export type WebCryptoEncryptionRequest = EncryptionRequest<
  WebCryptoAlgorithmSuite
>
export type WebCryptoDecryptionRequest = DecryptionRequest<
  WebCryptoAlgorithmSuite
>
export type WebCryptoGetEncryptionMaterials = GetEncryptionMaterials<
  WebCryptoAlgorithmSuite
>
export type WebCryptoGetDecryptMaterials = GetDecryptMaterials<
  WebCryptoAlgorithmSuite
>

/**
 * The DefaultCryptographicMaterialsManager is a specific implementation of the CryptographicMaterialsManager.
 * New cryptography materials managers SHOULD extend from WebCryptoMaterialsManager.
 * Users should never need to create an instance of a DefaultCryptographicMaterialsManager.
 */
export class WebCryptoDefaultCryptographicMaterialsManager
  implements WebCryptoMaterialsManager {
  readonly keyring!: KeyringWebCrypto
  constructor(keyring: KeyringWebCrypto) {
    /* Precondition: keyrings must be a KeyringWebCrypto. */
    needs(keyring instanceof KeyringWebCrypto, 'Unsupported type.')
    readOnlyProperty(this, 'keyring', keyring)
  }
  async getEncryptionMaterials({
    suite,
    encryptionContext,
  }: WebCryptoEncryptionRequest): Promise<WebCryptoEncryptionMaterial> {
    suite =
      suite ||
      new WebCryptoAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
      )

    /* Precondition: WebCryptoDefaultCryptographicMaterialsManager must reserve the ENCODED_SIGNER_KEY constant from @aws-crypto/serialize.
     * A CryptographicMaterialsManager can change entries to the encryptionContext
     * but changing these values has consequences.
     * The DefaultCryptographicMaterialsManager uses the value in the encryption context to store public signing key.
     * If the caller is using this value in their encryption context the Default CMM is probably not the CMM they want to use.
     */
    needs(
      !Object.prototype.hasOwnProperty.call(
        encryptionContext,
        ENCODED_SIGNER_KEY
      ),
      `Reserved encryptionContext value ${ENCODED_SIGNER_KEY} not allowed.`
    )

    const material = await this.keyring.onEncrypt(
      await this._initializeEncryptionMaterial(suite, encryptionContext)
    )

    /* Postcondition: The WebCryptoEncryptionMaterial must contain a valid dataKey.
     * This verifies that the data key matches the algorithm suite specification
     * and that the unencrypted data key is non-NULL.
     * See: cryptographic_materials.ts, `getUnencryptedDataKey`
     */
    needs(material.hasValidKey(), 'Unencrypted data key is invalid.')

    /* Postcondition: The WebCryptoEncryptionMaterial must contain at least 1 EncryptedDataKey. */
    needs(
      material.encryptedDataKeys.length,
      'No EncryptedDataKeys: the ciphertext can never be decrypted.'
    )

    return material
  }

  async decryptMaterials({
    suite,
    encryptedDataKeys,
    encryptionContext,
  }: WebCryptoDecryptionRequest): Promise<WebCryptoDecryptionMaterial> {
    const material = await this.keyring.onDecrypt(
      await this._initializeDecryptionMaterial(suite, encryptionContext),
      encryptedDataKeys.slice()
    )

    /* Postcondition: The WebCryptoDecryptionMaterial must contain a valid dataKey.
     * See: cryptographic_materials.ts, `getUnencryptedDataKey` also verifies
     * that the unencrypted data key has not been manipulated,
     * that the data key matches the algorithm suite specification
     * and that the unencrypted data key is non-NULL.
     */
    needs(material.hasValidKey(), 'Unencrypted data key is invalid.')

    return material
  }

  async _initializeEncryptionMaterial(
    suite: WebCryptoAlgorithmSuite,
    encryptionContext: EncryptionContext
  ) {
    const { signatureCurve: namedCurve } = suite

    /* Check for early return (Postcondition): The WebCryptoAlgorithmSuite specification must support a signatureCurve to generate a signing key. */
    if (!namedCurve)
      return new WebCryptoEncryptionMaterial(suite, encryptionContext)

    const backend = await getWebCryptoBackend()
    const subtle = getNonZeroByteBackend(backend)

    const webCryptoAlgorithm = { name: 'ECDSA', namedCurve }
    const extractable = false
    const usages = ['sign']
    const format = 'raw'

    const { publicKey, privateKey } = await subtle.generateKey(
      webCryptoAlgorithm,
      extractable,
      usages
    )
    const publicKeyBytes = await subtle.exportKey(format, publicKey)
    const compressPoint = SignatureKey.encodeCompressPoint(
      new Uint8Array(publicKeyBytes),
      suite
    )
    const signatureKey = new SignatureKey(privateKey, compressPoint, suite)
    return new WebCryptoEncryptionMaterial(suite, {
      ...encryptionContext,
      [ENCODED_SIGNER_KEY]: toBase64(compressPoint),
    }).setSignatureKey(signatureKey)
  }

  async _initializeDecryptionMaterial(
    suite: WebCryptoAlgorithmSuite,
    encryptionContext: EncryptionContext
  ) {
    const { signatureCurve: namedCurve } = suite

    /* Check for early return (Postcondition): The WebCryptoAlgorithmSuite specification must support a signatureCurve to extract a verification key. */
    if (!namedCurve)
      return new WebCryptoDecryptionMaterial(suite, encryptionContext)

    /* Precondition: WebCryptoDefaultCryptographicMaterialsManager If the algorithm suite specification requires a signatureCurve a context must exist. */
    if (!encryptionContext)
      throw new Error(
        'Encryption context does not contain required public key.'
      )

    const { [ENCODED_SIGNER_KEY]: compressPoint } = encryptionContext

    /* Precondition: WebCryptoDefaultCryptographicMaterialsManager The context must contain the public key. */
    needs(compressPoint, 'Context does not contain required public key.')

    const backend = await getWebCryptoBackend()
    const subtle = getNonZeroByteBackend(backend)
    const webCryptoAlgorithm = { name: 'ECDSA', namedCurve }
    const extractable = false
    const usages = ['verify']
    const format = 'raw'

    const publicKeyBytes = VerificationKey.decodeCompressPoint(
      fromBase64(compressPoint),
      suite
    )
    const publicKey = await subtle.importKey(
      format,
      publicKeyBytes,
      webCryptoAlgorithm,
      extractable,
      usages
    )

    return new WebCryptoDecryptionMaterial(
      suite,
      encryptionContext
    ).setVerificationKey(new VerificationKey(publicKey, suite))
  }
}

immutableBaseClass(WebCryptoDefaultCryptographicMaterialsManager)
