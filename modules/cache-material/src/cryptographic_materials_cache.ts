// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  EncryptionMaterial,
  DecryptionMaterial,
  SupportedAlgorithmSuites,
} from '@aws-crypto/material-management'

export interface CryptographicMaterialsCache<
  S extends SupportedAlgorithmSuites
> {
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
  getEncryptionMaterial(
    key: string,
    plaintextLength: number
  ): EncryptionMaterialEntry<S> | false
  getDecryptionMaterial(key: string): DecryptionMaterialEntry<S> | false
  del(key: string): void
}

export interface Entry<S extends SupportedAlgorithmSuites> {
  response: EncryptionMaterial<S> | DecryptionMaterial<S>
  bytesEncrypted: number
  messagesEncrypted: number
  readonly now: number
}

export interface EncryptionMaterialEntry<S extends SupportedAlgorithmSuites>
  extends Entry<S> {
  readonly response: EncryptionMaterial<S>
}

export interface DecryptionMaterialEntry<S extends SupportedAlgorithmSuites>
  extends Entry<S> {
  readonly response: DecryptionMaterial<S>
}
