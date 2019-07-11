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
  AwsEsdkKMSInterface, // eslint-disable-line no-unused-vars
  GenerateDataKeyResponse, // eslint-disable-line no-unused-vars
  RequiredGenerateDataKeyResponse, // eslint-disable-line no-unused-vars
  EncryptResponse, // eslint-disable-line no-unused-vars
  RequiredEncryptResponse, // eslint-disable-line no-unused-vars
  DecryptResponse, // eslint-disable-line no-unused-vars
  RequiredDecryptResponse // eslint-disable-line no-unused-vars
} from './kms_types'
import { regionFromKmsKeyArn } from './region_from_kms_key_arn'
import {
  EncryptionContext, // eslint-disable-line no-unused-vars
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  needs
} from '@aws-crypto/material-management' // eslint-disable-line no-unused-vars

export const KMS_PROVIDER_ID = 'aws-kms'

export async function generateDataKey<Client extends AwsEsdkKMSInterface> (
  clientProvider: KmsClientSupplier<Client>,
  NumberOfBytes: number,
  KeyId: string,
  EncryptionContext?: EncryptionContext,
  GrantTokens?: string[]
): Promise<RequiredGenerateDataKeyResponse|false> {
  const region = regionFromKmsKeyArn(KeyId)
  const client = clientProvider(region)

  /* Check for early return (Postcondition): Client region was not provided. */
  if (!client) return false
  const v2vsV3Response = client.generateDataKey({ KeyId, GrantTokens, NumberOfBytes, EncryptionContext })
  const v2vsV3Promise = 'promise' in v2vsV3Response
    ? v2vsV3Response.promise()
    : v2vsV3Response
  const dataKey = await v2vsV3Promise

  return safeGenerateDataKey(dataKey)
}

export async function encrypt<Client extends AwsEsdkKMSInterface> (
  clientProvider: KmsClientSupplier<Client>,
  Plaintext: Uint8Array,
  KeyId: string,
  EncryptionContext?: EncryptionContext,
  GrantTokens?: string[]
): Promise<RequiredEncryptResponse|false> {
  const region = regionFromKmsKeyArn(KeyId)
  const client = clientProvider(region)

  /* Check for early return (Postcondition): Client region was not provided. */
  if (!client) return false

  const v2vsV3Response = client.encrypt({ KeyId, Plaintext, EncryptionContext, GrantTokens })
  const v2vsV3Promise = 'promise' in v2vsV3Response
    ? v2vsV3Response.promise()
    : v2vsV3Response
  const kmsEDK = await v2vsV3Promise

  return safeEncryptOutput(kmsEDK)
}

export async function decrypt<Client extends AwsEsdkKMSInterface> (
  clientProvider: KmsClientSupplier<Client>,
  { providerId, providerInfo, encryptedDataKey }: EncryptedDataKey,
  EncryptionContext?: EncryptionContext,
  GrantTokens?: string[]
): Promise<RequiredDecryptResponse|false> {
  /* Precondition:  The EDK must be a KMS edk. */
  needs(providerId === KMS_PROVIDER_ID, 'Unsupported providerId')
  const region = regionFromKmsKeyArn(providerInfo)
  const client = clientProvider(region)
  /* Check for early return (Postcondition): Client region was not provided. */
  if (!client) return false

  const v2vsV3Response = client.decrypt({ CiphertextBlob: encryptedDataKey, EncryptionContext, GrantTokens })
  const v2vsV3Promise = 'promise' in v2vsV3Response
    ? v2vsV3Response.promise()
    : v2vsV3Response
  const dataKey = await v2vsV3Promise

  return safeDecryptOutput(dataKey)
}

export function kmsResponseToEncryptedDataKey ({
  KeyId: providerInfo,
  CiphertextBlob: encryptedDataKey
}: RequiredEncryptResponse) {
  return new EncryptedDataKey({ providerId: KMS_PROVIDER_ID, providerInfo, encryptedDataKey })
}

function safeGenerateDataKey (
  dataKey: GenerateDataKeyResponse
): RequiredGenerateDataKeyResponse {
  /* Postcondition: KMS must return serializable generate data key. */
  needs(typeof dataKey.KeyId === 'string' &&
    dataKey.Plaintext instanceof Uint8Array &&
    dataKey.CiphertextBlob instanceof Uint8Array, 'Malformed KMS response.')

  return <RequiredGenerateDataKeyResponse>safePlaintext(<RequiredGenerateDataKeyResponse>dataKey)
}

function safeEncryptOutput (
  dataKey: EncryptResponse
): RequiredEncryptResponse {
  /* Postcondition: KMS must return serializable encrypted data key. */
  needs(typeof dataKey.KeyId === 'string' &&
    dataKey.CiphertextBlob instanceof Uint8Array, 'Malformed KMS response.')

  return <RequiredEncryptResponse>dataKey
}

function safeDecryptOutput (
  dataKey: DecryptResponse
): RequiredDecryptResponse {
  /* Postcondition: KMS must return usable decrypted key. */
  needs(typeof dataKey.KeyId === 'string' &&
    dataKey.Plaintext instanceof Uint8Array, 'Malformed KMS response.')

  return <RequiredDecryptResponse>safePlaintext(<RequiredDecryptResponse>dataKey)
}

function safePlaintext (dataKey: RequiredDecryptResponse | RequiredGenerateDataKeyResponse): RequiredDecryptResponse | RequiredGenerateDataKeyResponse {
  /* The KMS Client *may* return a Buffer that is not isolated.
   * i.e. the byteOffset !== 0.
   * This means that the unencrypted data key is possibly accessible to someone else.
   * If this is the node shared Buffer, then other code within this process _could_ find this secret.
   * Copy Plaintext to an isolated ArrayBuffer and zero the Plaintext.
   * This means that this function will *always* zero out the value returned to it from the KMS client.
   * While this is safe to do here, copying this code somewhere else may produce unexpected results.
   */
  const { Plaintext } = dataKey
  dataKey.Plaintext = new Uint8Array(Plaintext)
  Plaintext.fill(0)
  return dataKey
}
