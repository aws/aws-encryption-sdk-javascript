// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeMaterialsManager,
  EncryptionRequest,
  DecryptionRequest,
  EncryptionContext,
  NodeAlgorithmSuite,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  SignatureKey,
  needs,
  VerificationKey,
  immutableClass,
  readOnlyProperty,
  KeyringNode,
  GetEncryptionMaterials,
  GetDecryptMaterials,
  CommitmentPolicySuites,
} from '@aws-crypto/material-management'

import { ENCODED_SIGNER_KEY } from '@aws-crypto/serialize'

import { createECDH } from 'crypto'

export type NodeEncryptionRequest = EncryptionRequest<NodeAlgorithmSuite>
export type NodeDecryptionRequest = DecryptionRequest<NodeAlgorithmSuite>
export type NodeGetEncryptionMaterials =
  GetEncryptionMaterials<NodeAlgorithmSuite>
export type NodeGetDecryptMaterials = GetDecryptMaterials<NodeAlgorithmSuite>

/**
 * The NodeDefaultCryptographicMaterialsManager is a specific implementation of the CryptographicMaterialsManager.
 * New cryptography materials managers SHOULD extend from NodeMaterialsManager.
 * Users should never need to create an instance of a NodeDefaultCryptographicMaterialsManager.
 */
export class NodeDefaultCryptographicMaterialsManager
  implements NodeMaterialsManager
{
  declare readonly keyring: KeyringNode
  constructor(keyring: KeyringNode) {
    /* Precondition: keyrings must be a KeyringNode. */
    needs(keyring instanceof KeyringNode, 'Unsupported type.')
    readOnlyProperty(this, 'keyring', keyring)
  }

  async getEncryptionMaterials({
    suite,
    encryptionContext,
    commitmentPolicy,
  }: NodeEncryptionRequest): Promise<NodeEncryptionMaterial> {
    suite =
      suite ||
      new NodeAlgorithmSuite(
        CommitmentPolicySuites[commitmentPolicy].defaultAlgorithmSuite
      )

    /* Precondition: NodeDefaultCryptographicMaterialsManager must reserve the ENCODED_SIGNER_KEY constant from @aws-crypto/serialize.
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
      this._initializeEncryptionMaterial(suite, encryptionContext)
    )

    /* Postcondition: The NodeEncryptionMaterial must contain a valid dataKey.
     * This verifies that the data key matches the algorithm suite specification
     * and that the unencrypted data key is non-NULL.
     * See: cryptographic_materials.ts, `getUnencryptedDataKey`
     */
    needs(material.getUnencryptedDataKey(), 'Unencrypted data key is invalid.')

    /* Postcondition: The NodeEncryptionMaterial must contain at least 1 EncryptedDataKey. */
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
  }: NodeDecryptionRequest): Promise<NodeDecryptionMaterial> {
    const material = await this.keyring.onDecrypt(
      this._initializeDecryptionMaterial(suite, encryptionContext),
      encryptedDataKeys.slice()
    )

    /* Postcondition: The NodeDecryptionMaterial must contain a valid dataKey.
     * See: cryptographic_materials.ts, `getUnencryptedDataKey` also verifies
     * that the unencrypted data key has not been manipulated,
     * that the data key matches the algorithm suite specification
     * and that the unencrypted data key is non-NULL.
     */
    needs(material.getUnencryptedDataKey(), 'Unencrypted data key is invalid.')

    return material
  }

  _initializeEncryptionMaterial(
    suite: NodeAlgorithmSuite,
    encryptionContext: EncryptionContext
  ) {
    const { signatureCurve: namedCurve } = suite

    /* Check for early return (Postcondition): The algorithm suite specification must support a signatureCurve to generate a ECDH key. */
    if (!namedCurve) return new NodeEncryptionMaterial(suite, encryptionContext)

    const ecdh = createECDH(namedCurve)
    ecdh.generateKeys()
    // @ts-ignore I want a compressed buffer.
    const compressPoint = ecdh.getPublicKey(undefined, 'compressed')
    const privateKey = ecdh.getPrivateKey()
    const signatureKey = new SignatureKey(
      privateKey,
      new Uint8Array(compressPoint),
      suite
    )

    return new NodeEncryptionMaterial(suite, {
      ...encryptionContext,
      [ENCODED_SIGNER_KEY]: compressPoint.toString('base64'),
    }).setSignatureKey(signatureKey)
  }

  _initializeDecryptionMaterial(
    suite: NodeAlgorithmSuite,
    encryptionContext: EncryptionContext
  ) {
    const { signatureCurve: namedCurve } = suite

    if (!namedCurve) {
      /* Precondition: NodeDefaultCryptographicMaterialsManager The context must not contain a public key for a non-signing algorithm suite. */
      needs(
        !Object.prototype.hasOwnProperty.call(
          encryptionContext,
          ENCODED_SIGNER_KEY
        ),
        'Encryption context contains public verification key for unsigned algorithm suite.'
      )

      /* Check for early return (Postcondition): The algorithm suite specification must support a signatureCurve to load a signature key. */
      return new NodeDecryptionMaterial(suite, encryptionContext)
    }

    /* Precondition: NodeDefaultCryptographicMaterialsManager If the algorithm suite specification requires a signatureCurve a context must exist. */
    if (!encryptionContext)
      throw new Error(
        'Encryption context does not contain required public key.'
      )

    const { [ENCODED_SIGNER_KEY]: compressPoint } = encryptionContext

    /* Precondition: NodeDefaultCryptographicMaterialsManager The context must contain the public key. */
    needs(compressPoint, 'Context does not contain required public key.')

    const publicKeyBytes = VerificationKey.decodeCompressPoint(
      Buffer.from(compressPoint, 'base64'),
      suite
    )

    return new NodeDecryptionMaterial(
      suite,
      encryptionContext
    ).setVerificationKey(new VerificationKey(publicKeyBytes, suite))
  }
}
immutableClass(NodeDefaultCryptographicMaterialsManager)
