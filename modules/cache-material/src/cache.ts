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
  EncryptionResponse, // eslint-disable-line no-unused-vars
  DecryptionResponse, // eslint-disable-line no-unused-vars
  SupportedAlgorithmSuites // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'

export interface Cache<S extends SupportedAlgorithmSuites> {
  putEncryptionResponse(
    key: string,
    response: EncryptionResponse<S>,
    plaintextLength: number,
    maxAge?: number
  ): void
  putDecryptionResponse(
    key: string,
    response: DecryptionResponse<S>,
    maxAge?: number
  ): void
  getEncryptionResponse(key: string, plaintextLength: number): EncryptionResponseEntry<S>|false
  getDecryptionResponse(key: string): DecryptionResponseEntry<S>|false
  del(key: string): void
}

export interface Entry<S extends SupportedAlgorithmSuites> {
  readonly response: EncryptionResponse<S>|DecryptionResponse<S>
  bytesEncrypted: number
  messagesEncrypted: number
  readonly now: number
}

export interface EncryptionResponseEntry<S extends SupportedAlgorithmSuites> extends Entry<S> {
  readonly response: EncryptionResponse<S>
}

export interface DecryptionResponseEntry<S extends SupportedAlgorithmSuites> extends Entry<S> {
  readonly response: DecryptionResponse<S>
}
