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

import {
  MixedBackendCryptoKey // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'

export enum RsaPadding {
  OAEP_SHA1_MFG1 = 'OAEP_SHA1_MFG1', // eslint-disable-line no-unused-vars
  OAEP_SHA256_MFG1 = 'OAEP_SHA256_MFG1', // eslint-disable-line no-unused-vars
}

export enum Format {
  raw = 'raw', // eslint-disable-line no-unused-vars
  pkcs8 = 'pkcs8', // eslint-disable-line no-unused-vars
  spki = 'spki', // eslint-disable-line no-unused-vars
}

// RSA_PKCS1, https://github.com/aws/aws-encryption-sdk-python/blob/master/src/aws_encryption_sdk/identifiers.py#L262
export enum JsonWebKeyRsaAlg {
  'RSA-OAEP' = 'RSA-OAEP',
  'RSA-OAEP-256' = 'RSA-OAEP-256'
}

export type RsaWrappingKeyHash = {
  name: 'SHA-1' | 'SHA-256'
}

export type RsaWrappingKeyAlgorithm = {
  name: 'RSA-OAEP'
  hash: Readonly<RsaWrappingKeyHash>
}

export interface BinaryKey {
  format: Format | keyof typeof Format
  key: Uint8Array
  padding: RsaPadding | keyof typeof RsaPadding
}

export interface RsaJsonWebKey extends JsonWebKey {
  alg: keyof typeof JsonWebKeyRsaAlg
}

export type RsaImportableKey = RsaJsonWebKey | BinaryKey

export type RsaKeyringWebCryptoInput = {
  keyNamespace: string
  keyName: string
  privateKey?: CryptoKey|MixedBackendCryptoKey
  publicKey?: CryptoKey
}
