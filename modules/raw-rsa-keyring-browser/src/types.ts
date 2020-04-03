// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  MixedBackendCryptoKey, // eslint-disable-line no-unused-vars
  AwsEsdkJsCryptoKey // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'

export enum RsaPadding {
  OAEP_SHA1_MFG1 = 'OAEP_SHA1_MFG1', // eslint-disable-line no-unused-vars
  OAEP_SHA256_MFG1 = 'OAEP_SHA256_MFG1', // eslint-disable-line no-unused-vars
  OAEP_SHA384_MFG1 = 'OAEP_SHA384_MFG1', // eslint-disable-line no-unused-vars
  OAEP_SHA512_MFG1 = 'OAEP_SHA512_MFG1', // eslint-disable-line no-unused-vars
}

export enum Format {
  raw = 'raw', // eslint-disable-line no-unused-vars
  pkcs8 = 'pkcs8', // eslint-disable-line no-unused-vars
  spki = 'spki', // eslint-disable-line no-unused-vars
}

// RSA_PKCS1, https://github.com/aws/aws-encryption-sdk-python/blob/master/src/aws_encryption_sdk/identifiers.py#L262
export enum JsonWebKeyRsaAlg {
  'RSA-OAEP' = 'RSA-OAEP',
  'RSA-OAEP-256' = 'RSA-OAEP-256',
  'RSA-OAEP-384' = 'RSA-OAEP-384',
  'RSA-OAEP-512' = 'RSA-OAEP-512'
}

export enum RsaHash {
  'SHA-1' = 'SHA-1',
  'SHA-256' = 'SHA-256',
  'SHA-384' = 'SHA-384',
  'SHA-512' = 'SHA-512'
}

export type RsaWrappingKeyHash = Readonly<{
  name: keyof typeof RsaHash
}>

export type RsaWrappingKeyAlgorithm = Readonly<{
  name: keyof typeof JsonWebKeyRsaAlg
  hash: Readonly<RsaWrappingKeyHash>
}>

export interface BinaryKey {
  format: Format | keyof typeof Format
  key: Uint8Array
  padding: RsaPadding | keyof typeof RsaPadding
}

export interface RsaJsonWebKey extends JsonWebKey {
  alg: keyof typeof JsonWebKeyRsaAlg
}

export type RsaImportableKey = RsaJsonWebKey | BinaryKey

export type RawRsaKeyringWebCryptoInput = {
  keyNamespace: string
  keyName: string
  privateKey?: AwsEsdkJsCryptoKey|MixedBackendCryptoKey
  publicKey?: AwsEsdkJsCryptoKey
}
