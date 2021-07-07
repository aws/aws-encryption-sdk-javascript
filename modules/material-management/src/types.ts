// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NodeAlgorithmSuite } from './node_algorithms'
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms'
import { EncryptedDataKey } from './encrypted_data_key'
import {
  NodeEncryptionMaterial,
  WebCryptoEncryptionMaterial,
  NodeDecryptionMaterial,
  WebCryptoDecryptionMaterial,
} from './cryptographic_material'
import { CommitmentPolicy } from './algorithm_suites'

export type EncryptionContext = { [index: string]: string }

/* need to copy some things from DOM */
export interface AwsEsdkJsKeyAlgorithm {
  name: string
}
export type AwsEsdkJsKeyType = 'public' | 'private' | 'secret'
export type AwsEsdkJsKeyUsage =
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'deriveKey'
  | 'deriveBits'
  | 'wrapKey'
  | 'unwrapKey'

export interface AwsEsdkJsCryptoKey {
  readonly algorithm: AwsEsdkJsKeyAlgorithm
  readonly extractable: boolean
  readonly type: AwsEsdkJsKeyType
  readonly usages: AwsEsdkJsKeyUsage[]
}

export interface AwsEsdkJsCryptoKeyPair {
  readonly publicKey: AwsEsdkJsCryptoKey
  readonly privateKey: AwsEsdkJsCryptoKey
}

export type MixedBackendCryptoKey = {
  nonZeroByteCryptoKey: AwsEsdkJsCryptoKey
  zeroByteCryptoKey: AwsEsdkJsCryptoKey
}

export interface EncryptionRequest<
  S extends NodeAlgorithmSuite | WebCryptoAlgorithmSuite
> {
  readonly suite?: S
  readonly encryptionContext: EncryptionContext
  readonly commitmentPolicy: CommitmentPolicy
  readonly plaintextLength?: number
}

export interface DecryptionRequest<
  S extends NodeAlgorithmSuite | WebCryptoAlgorithmSuite
> {
  readonly suite: S
  readonly encryptionContext: EncryptionContext
  readonly encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
}

export type SupportedAlgorithmSuites =
  | NodeAlgorithmSuite
  | WebCryptoAlgorithmSuite

export type EncryptionMaterial<Suite> = Suite extends NodeAlgorithmSuite
  ? NodeEncryptionMaterial
  : Suite extends WebCryptoAlgorithmSuite
  ? WebCryptoEncryptionMaterial
  : never

export type DecryptionMaterial<Suite> = Suite extends NodeAlgorithmSuite
  ? NodeDecryptionMaterial
  : Suite extends WebCryptoAlgorithmSuite
  ? WebCryptoDecryptionMaterial
  : never

/* These are copies of the v12 Node.js types.
 * I copied them here to avoid exporting v12 types
 * and forcing consumers to install/use v12 in their projects.
 */
export type AwsEsdkKeyObjectType = 'secret' | 'public' | 'private'
export type AwsEsdkKeyFormat = 'pem' | 'der'
export type AwsEsdkKeyType = 'rsa' | 'dsa' | 'ec'
export interface AwsEsdkKeyExportOptions<T extends AwsEsdkKeyFormat> {
  type: 'pkcs1' | 'spki' | 'pkcs8' | 'sec1'
  format: T
  cipher?: string
  passphrase?: string | Buffer
}

export interface AwsEsdkKeyObject {
  asymmetricKeyType?: AwsEsdkKeyType
  /**
   * For asymmetric keys, this property represents the size of the embedded key in
   * bytes. This property is `undefined` for symmetric keys.
   */
  asymmetricKeySize?: number
  /**
   * This property exists only on asymmetric keys. Depending on the type of the key,
   * this object contains information about the key. None of the information obtained
   * through this property can be used to uniquely identify a key or to compromise the
   * security of the key.
   */
  asymmetricKeyDetails?: AwsEsdkAsymmetricKeyDetails
  export(options: AwsEsdkKeyExportOptions<'pem'>): string | Buffer
  export(options?: AwsEsdkKeyExportOptions<'der'>): Buffer
  export(options?: { format: 'jwk' }): AwsEsdkJsonWebKey
  symmetricSize?: number
  type: AwsEsdkKeyObjectType
}
export type AwsEsdkCreateSecretKey = (key: Uint8Array) => AwsEsdkKeyObject

export interface ClientOptions {
  commitmentPolicy: CommitmentPolicy
  maxEncryptedDataKeys: number | false
}

export type Newable<T> = { new (...args: any[]): T }

export interface AwsEsdkJsonWebKey {
  crv?: string
  d?: string
  dp?: string
  dq?: string
  e?: string
  k?: string
  kty?: string
  n?: string
  p?: string
  q?: string
  qi?: string
  x?: string
  y?: string
  [key: string]: unknown
}
export interface AwsEsdkAsymmetricKeyDetails {
  /**
   * Key size in bits (RSA, DSA).
   */
  modulusLength?: number
  /**
   * Public exponent (RSA).
   */
  publicExponent?: bigint
  /**
   * Size of q in bits (DSA).
   */
  divisorLength?: number
  /**
   * Name of the curve (EC).
   */
  namedCurve?: string
}
