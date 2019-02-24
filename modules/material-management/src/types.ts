/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import {AlgorithmSuite} from './algorithm_suites'
import {EncryptedDataKey} from './encrypted_data_key'
import {NodeEncryptionMaterial, WebCryptoEncryptionMaterial}  from './cryptographic_material'
import {NodeDecryptionMaterial, WebCryptoDecryptionMaterial}  from './cryptographic_material'

export type EncryptionContext = {[index: string]: string}

export type MixedBackendCryptoKey = {
  nonZeroByteCryptoKey: CryptoKey
  zeroByteCryptoKey: CryptoKey
}

export interface EncryptionRequest<S extends AlgorithmSuite> {
  readonly suite: S
  readonly encryptionContext: EncryptionContext
  readonly frameLength?: number
  readonly plaintextLength?: number
}

export interface DecryptionRequest<S extends AlgorithmSuite> {
  readonly suite: S
  readonly encryptionContext?: EncryptionContext
  readonly encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
}

export type EncryptionMaterial = NodeEncryptionMaterial|WebCryptoEncryptionMaterial
export type DecryptionMaterial = NodeDecryptionMaterial|WebCryptoDecryptionMaterial
