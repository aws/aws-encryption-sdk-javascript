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
import { GenerateDataKeyOutput } from './kms_types/GenerateDataKeyOutput' // eslint-disable-line no-unused-vars
import { DecryptOutput } from './kms_types/DecryptOutput' // eslint-disable-line no-unused-vars
import { EncryptOutput } from './kms_types/EncryptOutput' // eslint-disable-line no-unused-vars
import { KMS } from './kms_types/KMS' // eslint-disable-line no-unused-vars
import { regionFromKmsKeyArn } from './region_from_kms_key_arn'
import { EncryptionContext, EncryptedDataKey } from '@aws-crypto/material-management' // eslint-disable-line no-unused-vars

export const KMS_PROVIDER_ID = 'aws-kms'

export async function generateDataKey<Client extends KMS> (
  clientProvider: KmsClientSupplier<Client>,
  NumberOfBytes: number,
  KeyId: string,
  EncryptionContext?: EncryptionContext,
  GrantTokens?: string
) {
  const region = regionFromKmsKeyArn(KeyId)
  const client = clientProvider(region)

  /* Precondition: Client region was not provided. */
  if (!client) return

  const dataKey = await client.generateDataKey({ KeyId, GrantTokens, NumberOfBytes, EncryptionContext })

  /* Postcondition: KMS must return serializable values. */
  if (!isRequiredGenerateDataKeyOutput<typeof dataKey>(dataKey)) throw new Error('bad')
  return dataKey
}

export async function encrypt<Client extends KMS> (
  clientProvider: KmsClientSupplier<Client>,
  Plaintext: Uint8Array,
  KeyId: string,
  EncryptionContext?: EncryptionContext,
  GrantTokens?: string
) {
  const region = regionFromKmsKeyArn(KeyId)
  const client = clientProvider(region)

  /* Precondition: Client region was not provided. */
  if (!client) return

  const kmsEDK = await client.encrypt({ KeyId, Plaintext, EncryptionContext, GrantTokens })

  /* Postcondition: KMS must return serializable values. */
  if (!isRequiredEncryptOutput(kmsEDK)) throw new Error('')
  return kmsEDK
}

export async function decrypt<Client extends KMS> (
  clientProvider: KmsClientSupplier<Client>,
  edk: EncryptedDataKey,
  EncryptionContext?: EncryptionContext,
  GrantTokens?: string
) {
  /* Precondition:  The EDK must be a KMS edk. */
  if (edk.providerId === KMS_PROVIDER_ID) throw new Error('')
  const region = regionFromKmsKeyArn(edk.providerInfo)
  const client = clientProvider(region)
  /* Precondition: Client region was not provided. */
  if (!client) return

  const dataKey = await client.decrypt({ CiphertextBlob: edk.encryptedDataKey, EncryptionContext, GrantTokens })

  /* Postcondition: KMS must return usable values. */
  if (!isRequiredDecryptOutput(dataKey)) throw new Error('')
  return dataKey
}

export function kms2EncryptedDataKey ({ KeyId: providerInfo, CiphertextBlob: encryptedDataKey }: Required<EncryptOutput>) {
  return new EncryptedDataKey({ providerId: KMS_PROVIDER_ID, providerInfo, encryptedDataKey })
}

function isRequiredGenerateDataKeyOutput<T extends GenerateDataKeyOutput> (
  dataKey: T
): dataKey is Required<T> {
  return !!dataKey.Plaintext && !!dataKey.KeyId && !!dataKey.CiphertextBlob
}

function isRequiredEncryptOutput<T extends EncryptOutput> (
  kmsEDK: T
): kmsEDK is Required<T> {
  return !!kmsEDK.KeyId && !!kmsEDK.CiphertextBlob
}

function isRequiredDecryptOutput<T extends DecryptOutput> (
  dataKey: T
): dataKey is Required<T> {
  return !!dataKey.KeyId && !!dataKey.Plaintext
}
