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

import { KmsClientSupplier } from './kms_client_supplier' // eslint-disable-line no-unused-vars
import {
  needs,
  Keyring, // eslint-disable-line no-unused-vars
  EncryptionMaterial, // eslint-disable-line no-unused-vars
  DecryptionMaterial, // eslint-disable-line no-unused-vars
  SupportedAlgorithmSuites, // eslint-disable-line no-unused-vars
  EncryptionContext, // eslint-disable-line no-unused-vars
  KeyringTrace, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  immutableClass,
  readOnlyProperty
} from '@aws-crypto/material-management'
import { KMS_PROVIDER_ID, generateDataKey, encrypt, decrypt, kms2EncryptedDataKey } from './helpers'
import { KMS } from './kms_types/KMS' // eslint-disable-line no-unused-vars
import { DecryptOutput } from './kms_types/DecryptOutput' // eslint-disable-line no-unused-vars
import { regionFromKmsKeyArn } from './region_from_kms_key_arn'

export interface KmsKeyringInput<Client extends KMS> {
  clientProvider: KmsClientSupplier<Client>
  keyIds?: string[]
  generatorKeyId?: string
  grantTokens?: string
  discovery?: boolean
}

export interface KeyRing<S extends SupportedAlgorithmSuites, Client extends KMS> extends Keyring<S> {
  keyIds: ReadonlyArray<string>
  generatorKeyId?: string
  clientProvider: KmsClientSupplier<Client>
  grantTokens?: string
  isDiscovery: boolean
  _onEncrypt(material: EncryptionMaterial<S>, context?: EncryptionContext): Promise<EncryptionMaterial<S>>
  _onDecrypt(material: DecryptionMaterial<S>, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext): Promise<DecryptionMaterial<S>>
}

export interface KmsKeyRingConstructible<S extends SupportedAlgorithmSuites, Client extends KMS> {
  new(input: KmsKeyringInput<Client>): KeyRing<S, Client>
}

export interface KeyRingConstructible<S extends SupportedAlgorithmSuites> {
  new(): Keyring<S>
}

export function KmsKeyringClass<S extends SupportedAlgorithmSuites, Client extends KMS> (
  BaseKeyring: KeyRingConstructible<S>
): KmsKeyRingConstructible<S, Client> {
  class KmsKeyring extends BaseKeyring implements KeyRing<S, Client> {
    public keyIds!: ReadonlyArray<string>
    public generatorKeyId?: string
    public clientProvider!: KmsClientSupplier<Client>
    public grantTokens?: string
    public isDiscovery!: boolean

    constructor ({ clientProvider, generatorKeyId, keyIds = [], grantTokens, discovery }: KmsKeyringInput<Client>) {
      super()
      /* Precondition: This is an abstract class. (But TypeScript does not have a clean way to model this) */
      needs(this.constructor !== KmsKeyring, 'new KmsKeyring is not allowed')
      /* Precondition: A noop KmsKeyring is not allowed. */
      needs(!discovery && !generatorKeyId && !keyIds.length, 'Noop keyring is not allowed: Set a keyId or discovery')
      /* Precondition: A keyring can be either a Discovery or have keyIds configured. */
      needs(discovery && (generatorKeyId || keyIds.length), 'A keyring can be either a Discovery or have keyIds configured.')
      /* Precondition: All KMS key arns must be valid. */
      needs(!generatorKeyId || !!regionFromKmsKeyArn(generatorKeyId), 'Malformed arn.')
      needs(keyIds.every(keyarn => !!regionFromKmsKeyArn(keyarn)), 'Malformed arn.')
      /* Precondition: clientProvider needs to be a callable function. */
      needs(typeof clientProvider === 'function', 'Missing clientProvider')

      readOnlyProperty(this, 'clientProvider', clientProvider)
      readOnlyProperty(this, 'keyIds', Object.freeze(keyIds.slice()))
      readOnlyProperty(this, 'generatorKeyId', generatorKeyId)
      readOnlyProperty(this, 'grantTokens', grantTokens)
      readOnlyProperty(this, 'isDiscovery', !!discovery)
    }

    /* Keyrings *must* preserve the order of EDK's.  The generatorKeyId is the first on this list. */
    async _onEncrypt (material: EncryptionMaterial<S>, context?: EncryptionContext) {
      /* Check for early return (Postcondition): Discovery Keyrings do not encrypt. */
      if (this.isDiscovery) return material

      const keyIds = this.keyIds.slice()
      const { clientProvider, generatorKeyId, grantTokens } = this
      if (generatorKeyId && !material.hasUnencryptedDataKey) {
        const dataKey = await generateDataKey(clientProvider, material.suite.keyLengthBytes, generatorKeyId, context, grantTokens)
        /* Precondition: A generatorKeyId must generate if we do not have an unencrypted data key.
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
          /* Postcondition: The generated unencryptedDataKey length must match the algorithm specification.
          * See cryptographic_materials as setUnencryptedDataKey will throw in this case.
          */
          .setUnencryptedDataKey(dataKey.Plaintext, trace)
          .addEncryptedDataKey(kms2EncryptedDataKey(dataKey), KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      } else if (generatorKeyId) {
        keyIds.unshift(generatorKeyId)
      }

      /* Precondition: If a generator does not exist, an unencryptedDataKey *must* already exist.
      * Furthermore *only* CMK's explicitly designated as generators can generate data keys.
      * See cryptographic_materials as getUnencryptedDataKey will throw in this case.
      */
      const unencryptedDataKey = material.getUnencryptedDataKey()

      const flags = KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
      for (const kmsKey of keyIds) {
        const kmsEDK = await encrypt(clientProvider, unencryptedDataKey, kmsKey, context, grantTokens)

        /* clientProvider may not return a client, in this case there is not an EDK to add */
        if (kmsEDK) material.addEncryptedDataKey(kms2EncryptedDataKey(kmsEDK), flags)
      }

      return material
    }

    async _onDecrypt (material: DecryptionMaterial<S>, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext) {
      const keyIds = this.keyIds.slice()
      const { clientProvider, generatorKeyId, grantTokens } = this
      if (generatorKeyId) keyIds.unshift(generatorKeyId)

      /* If there are no key IDs in the list, keyring is in "discovery" mode and will attempt KMS calls with
      * every ARN it comes across in the message. If there are key IDs in the list, it will cross check the
      * ARN it reads with that list before attempting KMS calls. Note that if caller provided key IDs in
      * anything other than a CMK ARN format, the SDK will not attempt to decrypt those data keys, because
      * the EDK data format always specifies the CMK with the full (non-alias) ARN.
      */
      const decryptableEDKs = encryptedDataKeys
        .filter(({ providerId, providerInfo }) => {
          if (providerId !== KMS_PROVIDER_ID) return false
          /* Discovery keyrings can not have keyIds configured,
           * and non-discovery keyrings must have keyIds configured.
           */
          return this.isDiscovery || keyIds.includes(providerInfo)
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

        /* Postcondition: The decrypted unencryptedDataKey length must match the algorithm specification.
          * See cryptographic_materials as setUnencryptedDataKey will throw in this case.
          */
        material.setUnencryptedDataKey(dataKey.Plaintext, trace)
        return material
      }

      return material
    }
  }
  immutableClass(KmsKeyring)
  return KmsKeyring
}
