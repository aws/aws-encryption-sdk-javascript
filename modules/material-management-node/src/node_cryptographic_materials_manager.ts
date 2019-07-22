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
  NodeMaterialsManager, EncryptionRequest, DecryptionRequest, EncryptionContext, // eslint-disable-line no-unused-vars
  EncryptionResponse, DecryptionResponse, // eslint-disable-line no-unused-vars
  NodeAlgorithmSuite, NodeEncryptionMaterial, NodeDecryptionMaterial, SignatureKey,
  needs, VerificationKey, AlgorithmSuiteIdentifier,
  immutableClass, readOnlyProperty, KeyringNode,
  GetEncryptionMaterials, GetDecryptMaterials // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'

import { ENCODED_SIGNER_KEY } from '@aws-crypto/serialize'

import { createECDH } from 'crypto'

export type NodeEncryptionRequest = EncryptionRequest<NodeAlgorithmSuite>
export type NodeDecryptionRequest = DecryptionRequest<NodeAlgorithmSuite>
export type NodeEncryptionResponse = EncryptionResponse<NodeAlgorithmSuite>
export type NodeDecryptionResponse = DecryptionResponse<NodeAlgorithmSuite>
export type NodeGetEncryptionMaterials = GetEncryptionMaterials<NodeAlgorithmSuite>
export type NodeGetDecryptMaterials = GetDecryptMaterials<NodeAlgorithmSuite>

/**
 * The DefaultCryptographicMaterialsManager is a specific implementation of the CryptographicMaterialsManager.
 * New cryptography materials managers SHOULD extend from NodeMaterialsManager.
 * Users should never need to create an instance of a DefaultCryptographicMaterialsManager.
 */
export class NodeDefaultCryptographicMaterialsManager implements NodeMaterialsManager {
  readonly keyring!: KeyringNode
  constructor (keyring: KeyringNode) {
    /* Precondition: keyrings must be a KeyringNode. */
    needs(keyring instanceof KeyringNode, 'Unsupported type.')
    readOnlyProperty(this, 'keyring', keyring)
  }

  async getEncryptionMaterials ({ suite, encryptionContext }: NodeEncryptionRequest): Promise<NodeEncryptionResponse> {
    suite = suite || new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)

    const material = await this
      .keyring
      .onEncrypt(this._initializeEncryptionMaterial(suite, encryptionContext))

    /* Postcondition: The NodeEncryptionMaterial must contain a valid dataKey. */
    needs(material.getUnencryptedDataKey(), 'Unencrypted data key is invalid.')

    /* Postcondition: The NodeEncryptionMaterial must contain at least 1 EncryptedDataKey. */
    needs(material.encryptedDataKeys.length, 'No EncryptedDataKeys: the ciphertext can never be decrypted.')

    return { material }
  }

  async decryptMaterials ({ suite, encryptedDataKeys, encryptionContext }: NodeDecryptionRequest): Promise<NodeDecryptionResponse> {
    const material = await this
      .keyring
      .onDecrypt(this._initializeDecryptionMaterial(suite, encryptionContext), encryptedDataKeys.slice())

    /* Postcondition: The NodeDecryptionMaterial must contain a valid dataKey.
     * See: cryptographic_materials.ts, `getUnencryptedDataKey` also verifies
     * that the unencrypted data key has not been manipulated.
     */
    needs(material.getUnencryptedDataKey(), 'Unencrypted data key is invalid.')

    return { material }
  }

  _initializeEncryptionMaterial (suite: NodeAlgorithmSuite, encryptionContext: EncryptionContext) {
    const { signatureCurve: namedCurve } = suite

    /* Check for early return (Postcondition): The algorithm suite specification must support a signatureCurve to generate a ECDH key. */
    if (!namedCurve) return new NodeEncryptionMaterial(suite, encryptionContext)

    const ecdh = createECDH(namedCurve)
    ecdh.generateKeys()
    // @ts-ignore I want a compressed buffer.
    const compressPoint = ecdh.getPublicKey(undefined, 'compressed')
    const privateKey = ecdh.getPrivateKey()
    const signatureKey = new SignatureKey(privateKey, new Uint8Array(compressPoint), suite)

    return new NodeEncryptionMaterial(
      suite,
      {
        ...encryptionContext,
        [ENCODED_SIGNER_KEY]: compressPoint.toString('base64')
      }
    )
      .setSignatureKey(signatureKey)
  }

  _initializeDecryptionMaterial (suite: NodeAlgorithmSuite, encryptionContext: EncryptionContext) {
    const { signatureCurve: namedCurve } = suite

    /* Check for early return (Postcondition): The algorithm suite specification must support a signatureCurve to load a signature key. */
    if (!namedCurve) return new NodeDecryptionMaterial(suite, encryptionContext)

    /* Precondition: NodeDefaultCryptographicMaterialsManager If the algorithm suite specification requires a signatureCurve a context must exist. */
    if (!encryptionContext) throw new Error('Encryption context does not contain required public key.')

    const { [ENCODED_SIGNER_KEY]: compressPoint } = encryptionContext

    /* Precondition: NodeDefaultCryptographicMaterialsManager The context must contain the public key. */
    needs(compressPoint, 'Context does not contain required public key.')

    const publicKeyBytes = VerificationKey.decodeCompressPoint(Buffer.from(compressPoint, 'base64'), suite)

    return new NodeDecryptionMaterial(suite, encryptionContext)
      .setVerificationKey(new VerificationKey(publicKeyBytes, suite))
  }
}
immutableClass(NodeDefaultCryptographicMaterialsManager)
