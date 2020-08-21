// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { EncryptionContext } from '@aws-crypto/material-management'

export interface DecryptRequest {
  KeyId?: string
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

export interface RequiredDecryptResponse extends Required<DecryptResponse> {
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

export interface RequiredEncryptResponse extends Required<EncryptResponse> {
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

export interface RequiredGenerateDataKeyResponse
  extends Required<GenerateDataKeyResponse> {
  CiphertextBlob: Uint8Array
  Plaintext: Uint8Array
}

export interface AwsSdkV2Response<Response> {
  promise(): Promise<Response>
}

export interface AwsEsdkKMSInterface {
  decrypt(
    args: DecryptRequest
  ): Promise<DecryptResponse> | AwsSdkV2Response<DecryptResponse>
  encrypt(
    args: EncryptRequest
  ): Promise<EncryptResponse> | AwsSdkV2Response<EncryptResponse>
  generateDataKey(
    args: GenerateDataKeyRequest
  ):
    | Promise<GenerateDataKeyResponse>
    | AwsSdkV2Response<GenerateDataKeyResponse>
}
