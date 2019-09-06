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

import { NodeAlgorithmSuite } from './node_algorithms' // eslint-disable-line no-unused-vars
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms' // eslint-disable-line no-unused-vars
import { EncryptedDataKey } from './encrypted_data_key' // eslint-disable-line no-unused-vars
import {
  NodeEncryptionMaterial, WebCryptoEncryptionMaterial, // eslint-disable-line no-unused-vars
  NodeDecryptionMaterial, WebCryptoDecryptionMaterial // eslint-disable-line no-unused-vars
} from './cryptographic_material'

export type EncryptionContext = {[index: string]: string}

/* need to copy some things from DOM */
export interface AwsEsdkJsKeyAlgorithm {
  name: string
}
export type AwsEsdkJsKeyType = 'public' | 'private' | 'secret'
export type AwsEsdkJsKeyUsage = 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'deriveKey' | 'deriveBits' | 'wrapKey' | 'unwrapKey'

export interface AwsEsdkJsCryptoKey {
  readonly algorithm: AwsEsdkJsKeyAlgorithm
  readonly extractable: boolean
  readonly type: AwsEsdkJsKeyType
  readonly usages: AwsEsdkJsKeyUsage[]
}

export type MixedBackendCryptoKey = {
  nonZeroByteCryptoKey: AwsEsdkJsCryptoKey
  zeroByteCryptoKey: AwsEsdkJsCryptoKey
}

export interface EncryptionRequest<S extends NodeAlgorithmSuite|WebCryptoAlgorithmSuite> {
  readonly suite?: S
  readonly encryptionContext: EncryptionContext
  readonly plaintextLength?: number
}

export interface DecryptionRequest<S extends NodeAlgorithmSuite|WebCryptoAlgorithmSuite> {
  readonly suite: S
  readonly encryptionContext: EncryptionContext
  readonly encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
}

export type SupportedAlgorithmSuites = NodeAlgorithmSuite|WebCryptoAlgorithmSuite

export type EncryptionMaterial<Suite> =
  Suite extends NodeAlgorithmSuite ? NodeEncryptionMaterial :
  Suite extends WebCryptoAlgorithmSuite ? WebCryptoEncryptionMaterial :
  never

export type DecryptionMaterial<Suite> =
  Suite extends NodeAlgorithmSuite ? NodeDecryptionMaterial :
  Suite extends WebCryptoAlgorithmSuite ? WebCryptoDecryptionMaterial :
  never

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
  export(options: AwsEsdkKeyExportOptions<'pem'>): string | Buffer
  export(options?: AwsEsdkKeyExportOptions<'der'>): Buffer
  symmetricSize?: number
  type: AwsEsdkKeyObjectType
}
export type AwsEsdkCreateSecretKey = (key: Uint8Array) => AwsEsdkKeyObject
