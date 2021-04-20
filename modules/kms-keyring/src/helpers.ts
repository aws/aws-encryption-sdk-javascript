// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { KmsClientSupplier } from './kms_client_supplier'
import {
  AwsEsdkKMSInterface,
  GenerateDataKeyResponse,
  RequiredGenerateDataKeyResponse,
  EncryptResponse,
  RequiredEncryptResponse,
  DecryptResponse,
  RequiredDecryptResponse,
} from './kms_types'
import { getRegionFromIdentifier } from './arn_parsing'
import {
  EncryptionContext,
  EncryptedDataKey,
  needs,
} from '@aws-crypto/material-management'

export const KMS_PROVIDER_ID = 'aws-kms'

export async function generateDataKey<Client extends AwsEsdkKMSInterface>(
  clientProvider: KmsClientSupplier<Client> | Client,
  NumberOfBytes: number,
  KeyId: string,
  EncryptionContext: EncryptionContext,
  GrantTokens?: string[]
): Promise<RequiredGenerateDataKeyResponse | false> {
  const client =
    typeof clientProvider === 'function'
      ? clientProvider(getRegionFromIdentifier(KeyId))
      : clientProvider

  /* Check for early return (Postcondition): clientProvider did not return a client for generateDataKey. */
  if (!client) return false
  const v2vsV3Response = client.generateDataKey({
    KeyId,
    GrantTokens,
    NumberOfBytes,
    EncryptionContext,
  })
  const v2vsV3Promise =
    'promise' in v2vsV3Response ? v2vsV3Response.promise() : v2vsV3Response
  const dataKey = await v2vsV3Promise

  return safeGenerateDataKey(dataKey)
}

export async function encrypt<Client extends AwsEsdkKMSInterface>(
  clientProvider: KmsClientSupplier<Client> | Client,
  Plaintext: Uint8Array,
  KeyId: string,
  EncryptionContext: EncryptionContext,
  GrantTokens?: string[]
): Promise<RequiredEncryptResponse | false> {
  const client =
    typeof clientProvider === 'function'
      ? clientProvider(getRegionFromIdentifier(KeyId))
      : clientProvider

  /* Check for early return (Postcondition): clientProvider did not return a client for encrypt. */
  if (!client) return false

  const v2vsV3Response = client.encrypt({
    KeyId,
    Plaintext,
    EncryptionContext,
    GrantTokens,
  })
  const v2vsV3Promise =
    'promise' in v2vsV3Response ? v2vsV3Response.promise() : v2vsV3Response
  const kmsEDK = await v2vsV3Promise

  return safeEncryptOutput(kmsEDK)
}

export async function decrypt<Client extends AwsEsdkKMSInterface>(
  clientProvider: KmsClientSupplier<Client> | Client,
  { providerId, providerInfo, encryptedDataKey }: EncryptedDataKey,
  EncryptionContext: EncryptionContext,
  GrantTokens?: string[]
): Promise<RequiredDecryptResponse | false> {
  /* Precondition:  The EDK must be a KMS edk. */
  needs(providerId === KMS_PROVIDER_ID, 'Unsupported providerId')
  const client =
    typeof clientProvider === 'function'
      ? clientProvider(getRegionFromIdentifier(providerInfo))
      : clientProvider

  /* Check for early return (Postcondition): clientProvider did not return a client for decrypt. */
  if (!client) return false

  /* The AWS KMS KeyId *must* be set. */
  const v2vsV3Response = client.decrypt({
    KeyId: providerInfo,
    CiphertextBlob: encryptedDataKey,
    EncryptionContext,
    GrantTokens,
  })
  const v2vsV3Promise =
    'promise' in v2vsV3Response ? v2vsV3Response.promise() : v2vsV3Response
  const dataKey = await v2vsV3Promise

  return safeDecryptOutput(dataKey)
}

export function kmsResponseToEncryptedDataKey({
  KeyId: providerInfo,
  CiphertextBlob: encryptedDataKey,
}: RequiredEncryptResponse) {
  return new EncryptedDataKey({
    providerId: KMS_PROVIDER_ID,
    providerInfo,
    encryptedDataKey,
  })
}

function safeGenerateDataKey(
  dataKey: GenerateDataKeyResponse
): RequiredGenerateDataKeyResponse {
  /* Postcondition: KMS must return serializable generate data key. */
  needs(
    typeof dataKey.KeyId === 'string' &&
      dataKey.Plaintext instanceof Uint8Array &&
      dataKey.CiphertextBlob instanceof Uint8Array,
    'Malformed KMS response.'
  )

  return safePlaintext(
    dataKey as RequiredGenerateDataKeyResponse
  ) as RequiredGenerateDataKeyResponse
}

function safeEncryptOutput(dataKey: EncryptResponse): RequiredEncryptResponse {
  /* Postcondition: KMS must return serializable encrypted data key. */
  needs(
    typeof dataKey.KeyId === 'string' &&
      dataKey.CiphertextBlob instanceof Uint8Array,
    'Malformed KMS response.'
  )

  return dataKey as RequiredEncryptResponse
}

function safeDecryptOutput(dataKey: DecryptResponse): RequiredDecryptResponse {
  /* Postcondition: KMS must return usable decrypted key. */
  needs(
    typeof dataKey.KeyId === 'string' &&
      dataKey.Plaintext instanceof Uint8Array,
    'Malformed KMS response.'
  )

  return safePlaintext(
    dataKey as RequiredDecryptResponse
  ) as RequiredDecryptResponse
}

function safePlaintext(
  dataKey: RequiredDecryptResponse | RequiredGenerateDataKeyResponse
): RequiredDecryptResponse | RequiredGenerateDataKeyResponse {
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
