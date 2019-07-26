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
  EncryptionMaterial, // eslint-disable-line no-unused-vars
  DecryptionMaterial, // eslint-disable-line no-unused-vars
  SupportedAlgorithmSuites, // eslint-disable-line no-unused-vars
  KeyringTrace, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  EncryptedDataKey // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'

export interface RawKeyRing<S extends SupportedAlgorithmSuites> {
  keyNamespace: string
  keyName: string
  _wrapKey: WrapKey<S>,
  _unwrapKey: UnwrapKey<S>,
  _filter: FilterEncryptedDataKey
}

export function _onEncrypt<S extends SupportedAlgorithmSuites, K extends RawKeyRing<S>> (
  randomBytes: (bytes: number) => Promise<Uint8Array>
) {
  return async function _onEncrypt (
    this: K,
    material: EncryptionMaterial<S>
  ): Promise<EncryptionMaterial<S>> {
    if (!material.hasUnencryptedDataKey) {
      const trace: KeyringTrace = {
        keyName: this.keyName,
        keyNamespace: this.keyNamespace,
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
      }
      const udk = await randomBytes(material.suite.keyLengthBytes)
      material.setUnencryptedDataKey(udk, trace)
    }
    return this._wrapKey(material)
  }
}

export function _onDecrypt<S extends SupportedAlgorithmSuites, K extends RawKeyRing<S>> () {
  return async function _onDecrypt (
    this: K,
    material: DecryptionMaterial<S>,
    encryptedDataKeys: EncryptedDataKey[]
  ): Promise<DecryptionMaterial<S>> {
    /* Check for early return (Postcondition): If the material is already valid, attempting to decrypt is a bad idea. */
    if (material.hasValidKey()) return material
    const edks = encryptedDataKeys.filter(this._filter, this)
    /* Check for early return (Postcondition): If there are not EncryptedDataKeys for this keyring, do nothing. */
    if (!edks.length) return material

    for (const edk of edks) {
      try {
        return await this._unwrapKey(material, edk)
      } catch (e) {
        // there should be some debug here?  or wrap?
        // Failures decrypt should not short-circuit the process
        // If the caller does not have access they may have access
        // through another Keyring.
      }
    }

    return material
  }
}

export interface WrapKey<S extends SupportedAlgorithmSuites> {
  (material: EncryptionMaterial<S>): Promise<EncryptionMaterial<S>>
}

export interface UnwrapKey<S extends SupportedAlgorithmSuites> {
  (material: DecryptionMaterial<S>, edk: EncryptedDataKey): Promise<DecryptionMaterial<S>>
}

export interface FilterEncryptedDataKey {
  (edk: EncryptedDataKey): boolean
}
