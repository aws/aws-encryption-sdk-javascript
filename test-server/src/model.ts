// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Wire shapes of the ESDKTestServer smithy model (decoded CBOR maps), plus the
 * mappings between the modeled enum names and the library's identifiers.
 */

import { AlgorithmSuiteIdentifier } from '@aws-crypto/client-node'
import { ServerError } from './errors'

export interface EncryptionContext {
  [key: string]: string
}

export interface DiscoveryFilterConfig {
  partition: string
  accountIds: string[]
}

export interface RawAesKeyringConfig {
  keyNamespace: string
  keyName: string
  wrappingKey: Uint8Array
  wrappingAlg: string
}

export interface RawRsaKeyringConfig {
  keyNamespace: string
  keyName: string
  paddingScheme: string
  publicKey?: Uint8Array
  privateKey?: Uint8Array
}

export interface AwsKmsKeyringConfig {
  kmsKeyId: string
  grantTokens?: string[]
}

export interface AwsKmsMultiKeyringConfig {
  generator?: string
  kmsKeyIds?: string[]
  grantTokens?: string[]
}

export interface AwsKmsDiscoveryKeyringConfig {
  discoveryFilter?: DiscoveryFilterConfig
  grantTokens?: string[]
}

export interface AwsKmsMrkDiscoveryKeyringConfig {
  region: string
  discoveryFilter?: DiscoveryFilterConfig
  grantTokens?: string[]
}

export interface AwsKmsHierarchicalKeyringConfig {
  branchKeyId: string
  keyStoreTableName: string
  logicalKeyStoreName: string
  kmsKeyArn: string
  ttlSeconds: number
}

export interface MultiKeyringConfig {
  generator?: KeyringConfig
  childKeyrings: KeyringConfig[]
}

/* Tagged union via optional members: exactly one variant set at runtime. */
export interface KeyringConfig {
  AwsKms?: AwsKmsKeyringConfig
  AwsKmsMrk?: AwsKmsKeyringConfig
  AwsKmsMultiKeyring?: AwsKmsMultiKeyringConfig
  AwsKmsMrkMultiKeyring?: AwsKmsMultiKeyringConfig
  AwsKmsDiscovery?: AwsKmsDiscoveryKeyringConfig
  AwsKmsMrkDiscovery?: AwsKmsMrkDiscoveryKeyringConfig
  AwsKmsRsa?: unknown
  RawAes?: RawAesKeyringConfig
  RawRsa?: RawRsaKeyringConfig
  AwsKmsHierarchical?: AwsKmsHierarchicalKeyringConfig
  Multi?: MultiKeyringConfig
}

export interface DefaultCmmConfig {
  keyring: KeyringConfig
}

export interface CachingCmmConfig {
  underlyingCMM: CmmConfig
  cacheLimitTtlSeconds: number
  partitionId?: string
  limitBytes?: number
  limitMessages?: number
}

/* Tagged union via optional members: exactly one variant set at runtime. */
export interface CmmConfig {
  Default?: DefaultCmmConfig
  RequiredEncryptionContext?: unknown
  Caching?: CachingCmmConfig
}

export interface EsdkClientConfig {
  commitmentPolicy: string
  maxEncryptedDataKeys?: number
  cmm: CmmConfig
}

export interface CreateClientRequest {
  config?: EsdkClientConfig
}

export interface EncryptRequest {
  clientId?: string
  plaintext?: Uint8Array
  encryptionContext?: EncryptionContext
  algorithmSuiteId?: string
  frameLength?: number
}

export interface DecryptRequest {
  clientId?: string
  ciphertext?: Uint8Array
  encryptionContext?: EncryptionContext
}

export interface EncryptStreamRequest extends EncryptRequest {
  plaintextLengthBound?: number
}

export type DecryptStreamRequest = DecryptRequest

/* Modeled ESDKAlgorithmSuiteId name -> library AlgorithmSuiteIdentifier. */
const SUITE_BY_MODEL_NAME: { [name: string]: AlgorithmSuiteIdentifier } = {
  ALG_AES_128_GCM_IV12_TAG16_NO_KDF:
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
  ALG_AES_192_GCM_IV12_TAG16_NO_KDF:
    AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16,
  ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16,
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256:
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256:
    AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256:
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
  ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
  ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
    AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY:
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
  ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384:
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
}

const MODEL_NAME_BY_SUITE = new Map<AlgorithmSuiteIdentifier, string>(
  Object.entries(SUITE_BY_MODEL_NAME).map(([name, id]) => [id, name])
)

export function toSuiteId(modelName: string): AlgorithmSuiteIdentifier {
  const suiteId = SUITE_BY_MODEL_NAME[modelName]
  if (suiteId === undefined) {
    throw new ServerError(`unknown algorithm suite id: ${modelName}`)
  }
  return suiteId
}

export function fromSuiteId(
  suiteId: AlgorithmSuiteIdentifier
): string | undefined {
  return MODEL_NAME_BY_SUITE.get(suiteId)
}
