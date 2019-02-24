/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import {AlgorithmSuite} from './algorithm_suites'
import {EncryptedDataKey} from './encrypted_data_key'
import {immutableBaseClass} from './immutable_class'

import {isEncryptionMaterial, isDecryptionMaterial} from './cryptographic_material'
import {DecryptionRequest, EncryptionContext, EncryptionMaterial, DecryptionMaterial} from './types'

/*
 * This public interface to the Keyring object is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */


export abstract class Keyring<E extends EncryptionMaterial, D extends DecryptionMaterial, S extends AlgorithmSuite> {
  async onEncrypt(material: E, context?: EncryptionContext): Promise<E> {
    /* Precondition: material must be a type of isEncryptionMaterial.
     * There are several security properties that NodeEncryptionMaterial and WebCryptoEncrypionMaterial
     * posses.
     * The unencryptedDataKey can only be written once.
     * If a data key has not already been generated, there must be no EDKs.
     * See cryptographic_materials.ts
     */
   if (!isEncryptionMaterial(material)) throw new Error('')

    const _material = await this._onEncrypt(material, context)

    /* Postcondition: _material must be a CryptographicMaterial instance.
     * Even if no unencrypted data key was added.  The algorithm suite specification
     * is bound in the material.
     */
    if (!isEncryptionMaterial(_material)) throw new Error('')

    /* Postcondition: The material objects must be the same.
     * See cryptographic_materials.ts.  The CryptographicMaterial objects
     * provide several security properties, including immutability of
     * the unencrypted data key and the ability to zero the data key.
     * This is insured by returning material, but if a Keyring is probably
     * not interacting with the material correctly.
     */
    if (material !== _material) throw new Error('')

    /* Postcondition: If this keyring generated data key, it must be the right length. 
     * See cryptographic_materials.ts This is handled in setUnencryptedDataKey
     * this condition is listed here to keep help keep track of important conditions
    */

    return material
  }

  abstract _onEncrypt(material: E, context?: EncryptionContext): Promise<E>

  async onDecrypt(request: DecryptionRequest<S>): Promise<D|void> {
    /* Precondition: Suite must be an AlgorithmSuite. */
    if (!(request.suite instanceof AlgorithmSuite)) throw new Error('')

    /* Precondition: encryptedDataKeys must all be EncryptedDataKey. */
    if (!request.encryptedDataKeys.every(edk => edk instanceof EncryptedDataKey)) throw new Error('')

    const material = await this._onDecrypt(request)

    /* Postcondition: If an EDK was decrypted it must be DecryptionMaterial. */
    if(material && !isDecryptionMaterial(material)) throw new Error('')

    /* Postcondition: If an EDK was decrypted, its length must agree with algorithm specification.
     * If this is not the case, it either means ciphertext was tampered
     * with or the keyring implementation is not setting the length properly.
     * See cryptographic_materials.ts The length condition is handled there
     */
    if (material && !material.hasUnencryptedDataKey) throw new Error('')

    return material
  }

  abstract _onDecrypt(request: DecryptionRequest<S>): Promise<D|void>
}

immutableBaseClass(Keyring)

