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

type KMSv3Node = import('@aws-sdk/client-kms-node').KMS
type KMSv3Browser = import('@aws-sdk/client-kms-browser').KMS
type KMSv2 = import('aws-sdk').KMS
type KMSv3 = KMSv3Browser | KMSv3Node

type KMSConfigV3Browser = import('@aws-sdk/client-kms-browser').KMSConfiguration
type KMSConfigV3Node = import('@aws-sdk/client-kms-node').KMSConfiguration
type KMSConfigV2 = import('aws-sdk').KMS.Types.ClientConfiguration

export type KMSConfiguration = KMSConfigV3Browser | KMSConfigV3Node | KMSConfigV2
export type KMS = KMSv3 | KMSv2

export type GenerateDataKeyInput<Client extends KMS> = Client extends KMSv3Node
  ? import('@aws-sdk/client-kms-node').GenerateDataKeyInput
  : Client extends KMSv3Browser
  ? import('@aws-sdk/client-kms-browser').GenerateDataKeyInput
  : Client extends KMSv2
  ? import('aws-sdk').KMS.GenerateDataKeyRequest
  : never

export type EncryptInput<Client extends KMS> = Client extends KMSv3Node
  ? import('@aws-sdk/client-kms-node').EncryptInput
  : Client extends KMSv3Browser
  ? import('@aws-sdk/client-kms-browser').EncryptInput
  : Client extends KMSv2
  ? import('aws-sdk').KMS.EncryptRequest
  : never

export type DecryptInput<Client extends KMS> = Client extends KMSv3Node
  ? import('@aws-sdk/client-kms-node').DecryptInput
  : Client extends KMSv3Browser
  ? import('@aws-sdk/client-kms-browser').DecryptInput
  : Client extends KMSv2
  ? import('aws-sdk').KMS.DecryptRequest
  : never

export type GenerateDataKeyOutput<Client extends KMS> = Client extends KMSv3Node
  ? import('@aws-sdk/client-kms-node').GenerateDataKeyOutput
  : Client extends KMSv3Browser
  ? import('@aws-sdk/client-kms-browser').GenerateDataKeyOutput
  : Client extends KMSv2
  ? import('aws-sdk').KMS.GenerateDataKeyResponse
  : never

export interface RequiredGenerateDataKeyOutput {
  CiphertextBlob: Uint8Array
  Plaintext: Uint8Array
  KeyId: string
}

export type EncryptOutput<Client extends KMS> = Client extends KMSv3Node
  ? import('@aws-sdk/client-kms-node').EncryptOutput
  : Client extends KMSv3Browser
  ? import('@aws-sdk/client-kms-browser').EncryptOutput
  : Client extends KMSv2
  ? import('aws-sdk').KMS.EncryptResponse
  : never

export interface RequiredEncryptOutput {
  CiphertextBlob: Uint8Array
  KeyId: string
}

export type DecryptOutput<Client extends KMS> = Client extends KMSv3Node
  ? import('@aws-sdk/client-kms-node').DecryptOutput
  : Client extends KMSv3Browser
  ? import('@aws-sdk/client-kms-browser').DecryptOutput
  : Client extends KMSv2
  ? import('aws-sdk').KMS.DecryptResponse
  : never

export interface RequiredDecryptOutput {
  KeyId: string
  Plaintext: Uint8Array
}

export type KMSOperations = keyof Pick<KMS, 'encrypt'| 'decrypt'| 'generateDataKey'>
