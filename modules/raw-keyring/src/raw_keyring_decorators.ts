// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  EncryptionMaterial,
  DecryptionMaterial,
  SupportedAlgorithmSuites,
  KeyringTrace,
  KeyringTraceFlag,
  EncryptedDataKey,
  needs,
} from '@aws-crypto/material-management'

export interface RawKeyRing<S extends SupportedAlgorithmSuites> {
  keyNamespace: string
  keyName: string
  _wrapKey: WrapKey<S>
  _unwrapKey: UnwrapKey<S>
  _filter: FilterEncryptedDataKey
}

export function _onEncrypt<
  S extends SupportedAlgorithmSuites,
  K extends RawKeyRing<S>
>(randomBytes: (bytes: number) => Promise<Uint8Array>) {
  return async function _onEncrypt(
    this: K,
    material: EncryptionMaterial<S>
  ): Promise<EncryptionMaterial<S>> {
    if (!material.hasUnencryptedDataKey) {
      const trace: KeyringTrace = {
        keyName: this.keyName,
        keyNamespace: this.keyNamespace,
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
      }
      const udk = await randomBytes(material.suite.keyLengthBytes)
      material.setUnencryptedDataKey(udk, trace)
    }
    return this._wrapKey(material)
  }
}

export function _onDecrypt<
  S extends SupportedAlgorithmSuites,
  K extends RawKeyRing<S>
>() {
  return async function _onDecrypt(
    this: K,
    material: DecryptionMaterial<S>,
    encryptedDataKeys: EncryptedDataKey[]
  ): Promise<DecryptionMaterial<S>> {
    /* Check for early return (Postcondition): If the material is already valid, attempting to decrypt is a bad idea. */
    if (material.hasValidKey()) return material
    const edks = encryptedDataKeys.filter(this._filter, this)
    /* Check for early return (Postcondition): If there are not EncryptedDataKeys for this keyring, do nothing. */
    if (!edks.length) return material

    const cmkErrors: Error[] = []

    for (const edk of edks) {
      try {
        return await this._unwrapKey(material, edk)
      } catch (e) {
        /* Failures onDecrypt should not short-circuit the process
         * If the caller does not have access they may have access
         * through another Keyring.
         */
        cmkErrors.push(e)
      }
    }

    /* Postcondition: An EDK must provide a valid data key or _unwrapKey must not have raised any errors.
     * If I have a data key,
     * decrypt errors can be ignored.
     * However, if I was unable to decrypt a data key AND I have errors,
     * these errors should bubble up.
     * Otherwise, the only error customers will see is that
     * the material does not have an unencrypted data key.
     * So I return a concatenated Error message
     */
    needs(
      material.hasValidKey() || (!material.hasValidKey() && !cmkErrors.length),
      cmkErrors.reduce(
        (m, e, i) => `${m} Error #${i + 1} \n ${e.stack} \n`,
        `Unable to decrypt data key ${this.keyName} ${this.keyNamespace}.\n `
      )
    )

    return material
  }
}

export interface WrapKey<S extends SupportedAlgorithmSuites> {
  (material: EncryptionMaterial<S>): Promise<EncryptionMaterial<S>>
}

export interface UnwrapKey<S extends SupportedAlgorithmSuites> {
  (material: DecryptionMaterial<S>, edk: EncryptedDataKey): Promise<
    DecryptionMaterial<S>
  >
}

export interface FilterEncryptedDataKey {
  (edk: EncryptedDataKey): boolean
}
