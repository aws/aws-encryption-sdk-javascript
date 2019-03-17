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

import { EncryptedDataKey } from './encrypted_data_key'
import { immutableBaseClass } from './immutable_class'

import { isEncryptionMaterial, isDecryptionMaterial } from './cryptographic_material'
import { EncryptionContext, EncryptionMaterial, DecryptionMaterial, SupportedAlgorithmSuites } from './types' // eslint-disable-line no-unused-vars
import { needs } from './needs'

/*
 * This public interface to the Keyring object is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */

export abstract class Keyring<S extends SupportedAlgorithmSuites> {
  async onEncrypt (material: EncryptionMaterial<S>, context?: EncryptionContext): Promise<EncryptionMaterial<S>> {
    /* Precondition: material must be a type of isEncryptionMaterial.
     * There are several security properties that NodeEncryptionMaterial and WebCryptoEncrypionMaterial
     * posses.
     * The unencryptedDataKey can only be written once.
     * If a data key has not already been generated, there must be no EDKs.
     * See cryptographic_materials.ts
     */
    needs(isEncryptionMaterial(material), 'Unsupported type of material.')

    const _material = await this._onEncrypt(material, context)

    /* Postcondition: The material objects must be the same.
     * See cryptographic_materials.ts.  The CryptographicMaterial objects
     * provide several security properties, including immutability of
     * the unencrypted data key and the ability to zero the data key.
     * This is insured by returning the same material.
     */
    needs(material === _material, 'New EncryptionMaterial instances can not be created.')

    /* Postcondition: If this keyring generated data key, it must be the right length.
     * See cryptographic_materials.ts This is handled in setUnencryptedDataKey
     * this condition is listed here to keep help keep track of important conditions
    */

    return material
  }

  abstract _onEncrypt(material: EncryptionMaterial<S>, context?: EncryptionContext): Promise<EncryptionMaterial<S>>

  /* NOTE: The order of EDK's passed to the onDecrypt function is a clear
   * intent on the part of the person who did the encryption.
   * The EDK's should always correspond to the order serialized.
   * It is the Keyrings responsibility to maintain this order.
   * The most clear example is from KMS.  KMS is a regional service.
   * This means that a call to decrypt an EDK must go to the
   * region that "owns" this EDK.  If the decryption is done
   * in a different region, then this call will travel over
   * the internet.  To control this behavior the person
   * who called encrypt can control the order of EDK.
   */
  async onDecrypt (material: DecryptionMaterial<S>, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext): Promise<DecryptionMaterial<S>> {
    /* Precondition: material must be DecryptionMaterial. */
    needs(isDecryptionMaterial(material), 'Unsupported material type.')

    /* Precondition: Attempt to decrypt iif material does not have an unencrypted data key. */
    if (material.hasValidKey()) return material

    /* Precondition: encryptedDataKeys must all be EncryptedDataKey. */
    needs(encryptedDataKeys.every(edk => edk instanceof EncryptedDataKey), 'Unsupported EncryptedDataKey type')

    const _material = await this._onDecrypt(material, encryptedDataKeys, context)

    /* Postcondition: The material objects must be the same.
     * See cryptographic_materials.ts.  The CryptographicMaterial objects
     * provide several security properties, including immutability of
     * the unencrypted data key and the ability to zero the data key.
     * This is insured by returning the same material.
     */
    needs(material === _material, 'New DecryptionMaterial instances can not be created.')

    /* See cryptographic_materials.ts The length condition is handled there.
     * But the condition is important and so repeated here.
     * Postcondition: If an EDK was decrypted, its length must agree with algorithm specification.
     * If this is not the case, it either means ciphertext was tampered
     * with or the keyring implementation is not setting the length properly.
     */

    return material
  }

  abstract _onDecrypt(material: DecryptionMaterial<S>, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext): Promise<DecryptionMaterial<S>>
}

immutableBaseClass(Keyring)
