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
  EncryptionMaterial, // eslint-disable-line no-unused-vars
  DecryptionMaterial, // eslint-disable-line no-unused-vars
  SupportedAlgorithmSuites // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'

export interface CryptographicMaterialsCache<S extends SupportedAlgorithmSuites> {
  putEncryptionMaterial(
    key: string,
    response: EncryptionMaterial<S>,
    plaintextLength: number,
    maxAge?: number
  ): void
  putDecryptionMaterial(
    key: string,
    response: DecryptionMaterial<S>,
    maxAge?: number
  ): void
  getEncryptionMaterial(key: string, plaintextLength: number): EncryptionMaterialEntry<S>|false
  getDecryptionMaterial(key: string): DecryptionMaterialEntry<S>|false
  del(key: string): void
}

export interface Entry<S extends SupportedAlgorithmSuites> {
  response: EncryptionMaterial<S>|DecryptionMaterial<S>
  bytesEncrypted: number
  messagesEncrypted: number
  readonly now: number
}

export interface EncryptionMaterialEntry<S extends SupportedAlgorithmSuites> extends Entry<S> {
  readonly response: EncryptionMaterial<S>
}

export interface DecryptionMaterialEntry<S extends SupportedAlgorithmSuites> extends Entry<S> {
  readonly response: DecryptionMaterial<S>
}
