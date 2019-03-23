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

import { KmsClientSupplier } from './kms_client_supplier' // eslint-disable-line no-unused-vars
import { needs, Keyring, EncryptionMaterial, DecryptionMaterial, SupportedAlgorithmSuites, EncryptionContext, KeyringTrace, KeyringTraceFlag, EncryptedDataKey, immutableClass } from '@aws-crypto/material-management' // eslint-disable-line no-unused-vars
import { KMS_PROVIDER_ID, generateDataKey, encrypt, decrypt, kms2EncryptedDataKey } from './helpers'
import { KMS } from './kms_types/KMS' // eslint-disable-line no-unused-vars
import { DecryptOutput } from './kms_types/DecryptOutput' // eslint-disable-line no-unused-vars
import { regionFromKmsKeyArn } from './region_from_kms_key_arn'

export interface KmsKeyringInput<Client extends KMS> {
  clientProvider: KmsClientSupplier<Client>
  kmsKeys?: string[]
  generatorKmsKey?: string
  grantTokens?: string
}

export abstract class KmsKeyring<S extends SupportedAlgorithmSuites, Client extends KMS> extends Keyring<S> {
  public kmsKeys: string[] = []
  public generatorKmsKey?: string
  public clientProvider: KmsClientSupplier<Client>
  public grantTokens?: string

  constructor ({ clientProvider, generatorKmsKey, kmsKeys = [], grantTokens }: KmsKeyringInput<Client>) {
    super()
    /* Precondition: All KMS key arns must be valid. */
    needs(!generatorKmsKey || !!regionFromKmsKeyArn(generatorKmsKey), 'Malformed arn.')
    needs(kmsKeys.every(keyarn => !!regionFromKmsKeyArn(keyarn)), 'Malformed arn.')
    /* Precondition: clientProvider needs to be a callable function. */
    needs(typeof clientProvider === 'function', '')

    this.clientProvider = clientProvider
    this.kmsKeys = kmsKeys
    this.generatorKmsKey = generatorKmsKey
    this.grantTokens = grantTokens
  }

  /* Keyrings *must* preserve the order of EDK's.  The generatorKmsKey is the first on this list. */
  async _onEncrypt (material: EncryptionMaterial<S>, context?: EncryptionContext) {
    const kmsKeys = this.kmsKeys.slice()
    const { clientProvider, generatorKmsKey, grantTokens } = this
    if (generatorKmsKey && !material.hasUnencryptedDataKey) {
      const dataKey = await generateDataKey(clientProvider, material.suite.keyLengthBytes, generatorKmsKey, context, grantTokens)
      /* Precondition: A generatorKmsKey must generate if we do not have an unencrypted data key.
       * Client supplier is allowed to return undefined if, for example, user wants to exclude particular
       * regions. But if we are here it means that user configured keyring with a KMS key that was
       * incompatible with the client supplier in use.
       */
      if (!dataKey) throw new Error('Generator KMS key did not generate a data key')

      const flags = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY |
        KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX |
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      const trace: KeyringTrace = { keyNamespace: KMS_PROVIDER_ID, keyName: dataKey.KeyId, flags }

      material
        /* Postcondition: The unencryptedDataKey length must match the algorithm specification.
         * See cryptographic_materials as setUnencryptedDataKey will throw in this case.
         */
        .setUnencryptedDataKey(dataKey.Plaintext, trace)
        .addEncryptedDataKey(kms2EncryptedDataKey(dataKey), KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    } else if (generatorKmsKey) {
      kmsKeys.unshift(generatorKmsKey)
    }

    /* Precondition: If a generator does not exist, an unencryptedDataKey *must* already exist.
     * Furthermore *only* CMK's explicitly designated as generators can generate data keys.
     * See cryptographic_materials as getUnencryptedDataKey will throw in this case.
     */
    const unencryptedDataKey = material.getUnencryptedDataKey()

    const flags = KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
    for (const kmsKey of kmsKeys) {
      const kmsEDK = await encrypt(clientProvider, unencryptedDataKey, kmsKey, context, grantTokens)

      /* clientProvider may not return a client, in this case there is not an EDK to add */
      if (kmsEDK) material.addEncryptedDataKey(kms2EncryptedDataKey(kmsEDK), flags)
    }

    return material
  }

  async _onDecrypt (material: DecryptionMaterial<S>, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext) {
    const kmsKeys = this.kmsKeys.slice()
    const { clientProvider, generatorKmsKey, grantTokens } = this
    if (generatorKmsKey) kmsKeys.unshift(generatorKmsKey)

    /* If there are no key IDs in the list, keyring is in "discovery" mode and will attempt KMS calls with
     * every ARN it comes across in the message. If there are key IDs in the list, it will cross check the
     * ARN it reads with that list before attempting KMS calls. Note that if caller provided key IDs in
     * anything other than a CMK ARN format, the SDK will not attempt to decrypt those data keys, because
     * the EDK data format always specifies the CMK with the full (non-alias) ARN.
     */
    const decryptableEDKs = encryptedDataKeys
      .filter(({ providerId, providerInfo }) => {
        if (providerId !== KMS_PROVIDER_ID) return false
        return kmsKeys.length
          ? kmsKeys.includes(providerInfo)
          : true
      })

    for (const edk of decryptableEDKs) {
      let dataKey: Required<DecryptOutput>|false = false
      try {
        dataKey = await decrypt(clientProvider, edk, context, grantTokens)
      } catch (e) {
        // there should be some debug here?  or wrap?
        // Failures decrypt should not short-circuit the process
        // If the caller does not have access they may have access
        // through another Keyring.
      }

      /* Check for early return (Postcondition): clientProvider may not return a client. */
      if (!dataKey) continue

      /* Postcondition: The KeyId from KMS must match the encoded KeyID. */
      needs(dataKey.KeyId === edk.providerInfo, 'KMS Decryption key does not match serialized provider.')

      const flags = KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX
      const trace: KeyringTrace = { keyNamespace: KMS_PROVIDER_ID, keyName: dataKey.KeyId, flags }

      /* Postcondition: The unencryptedDataKey length must match the algorithm specification.
        * See cryptographic_materials as setUnencryptedDataKey will throw in this case.
        */
      material.setUnencryptedDataKey(dataKey.Plaintext, trace)
      return material
    }

    return material
  }
}
immutableClass(KmsKeyring)
