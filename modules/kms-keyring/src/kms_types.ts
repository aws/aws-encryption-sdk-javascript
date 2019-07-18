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

import { EncryptionContext } from '@aws-crypto/material-management' // eslint-disable-line no-unused-vars

export interface DecryptRequest {
  CiphertextBlob: Uint8Array
  EncryptionContext?: EncryptionContext
  GrantTokens?: string[]
}

interface Blob {}
type Data = string | Buffer | Uint8Array | Blob
export interface DecryptResponse {
  KeyId?: string
  Plaintext?: Data
}

export interface RequiredDecryptResponse extends Required<DecryptResponse>{
  Plaintext: Uint8Array
}

export interface EncryptRequest {
  KeyId: string
  Plaintext: Uint8Array
  EncryptionContext?: EncryptionContext
  GrantTokens?: string[]
}
export interface EncryptResponse {
  CiphertextBlob?: Data
  KeyId?: string
}

export interface RequiredEncryptResponse extends Required<EncryptResponse>{
  CiphertextBlob: Uint8Array
}

export interface GenerateDataKeyRequest {
  KeyId: string
  EncryptionContext?: EncryptionContext
  NumberOfBytes?: number
  GrantTokens?: string[]
}

export interface GenerateDataKeyResponse {
  CiphertextBlob?: Data
  Plaintext?: Data
  KeyId?: string
}

export interface RequiredGenerateDataKeyResponse extends Required<GenerateDataKeyResponse>{
  CiphertextBlob: Uint8Array
  Plaintext: Uint8Array
}

export interface AwsSdkV2Response<Response> {
  promise(): Promise<Response>
}

export interface AwsEsdkKMSInterface {
  decrypt(args: DecryptRequest): Promise<DecryptResponse>|AwsSdkV2Response<DecryptResponse>
  encrypt(args: EncryptRequest): Promise<EncryptResponse>|AwsSdkV2Response<EncryptResponse>
  generateDataKey(args: GenerateDataKeyRequest): Promise<GenerateDataKeyResponse>|AwsSdkV2Response<GenerateDataKeyResponse>
}
