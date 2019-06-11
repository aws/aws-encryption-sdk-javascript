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
  SupportedAlgorithmSuites, // eslint-disable-line no-unused-vars
  DecryptionRequest, // eslint-disable-line no-unused-vars
  EncryptionRequest, // eslint-disable-line no-unused-vars
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  EncryptionContext // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'
import { serializeFactory, uInt16BE } from '@aws-crypto/serialize'
import { compare } from './portable_compare'

//  512 bits of 0 for padding between hashes in decryption materials cache ID generation.
const BIT_PAD_512 = Buffer.alloc(64)

export function buildCryptographicMaterialsCacheKeyHelpers<S extends SupportedAlgorithmSuites> (
  fromUtf8: (input: string) => Uint8Array,
  toUtf8: (input: Uint8Array) => string,
  sha512: (...data: ((Uint8Array|string))[]) => Promise<Uint8Array>
): CryptographicMaterialsCacheKeyHelpersInterface<S> {
  const {
    serializeEncryptionContext,
    serializeEncryptedDataKey
  } = serializeFactory(fromUtf8)

  return {
    buildEncryptionResponseCacheKey,
    buildDecryptionResponseCacheKey,
    encryptedDataKeysHash,
    encryptionContextHash
  }

  async function buildEncryptionResponseCacheKey (
    partition: string,
    { suite, encryptionContext }: EncryptionRequest<S>
  ) {
    const algorithmInfo = suite
      ? [new Uint8Array([1]), uInt16BE(suite.id)]
      : [new Uint8Array([0])]

    const key = await sha512(
      await sha512(fromUtf8(partition)),
      ...algorithmInfo,
      await encryptionContextHash(encryptionContext)
    )
    return toUtf8(key)
  }

  async function buildDecryptionResponseCacheKey (
    partition: string,
    { suite, encryptedDataKeys, encryptionContext }: DecryptionRequest<S>
  ) {
    const { id } = suite

    const key = await sha512(
      await sha512(fromUtf8(partition)),
      uInt16BE(id),
      ...(await encryptedDataKeysHash(encryptedDataKeys)),
      BIT_PAD_512,
      await encryptionContextHash(encryptionContext)
    )
    return toUtf8(key)
  }

  async function encryptedDataKeysHash (encryptedDataKeys: ReadonlyArray<EncryptedDataKey>) {
    const hashes = await Promise.all(
      encryptedDataKeys
        .map(serializeEncryptedDataKey)
        .map(edk => sha512(edk))
    )
    return hashes.sort(compare)
  }

  function encryptionContextHash (context?: EncryptionContext) {
    /* The AAD section is uInt16BE(length) + AAD
     * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
     * However, the RAW Keyring wants _only_ the ADD.
     * So, I just slice off the length.
     */
    const serializedContext = serializeEncryptionContext(context || {}).slice(2)
    return sha512(serializedContext)
  }
}

export interface CryptographicMaterialsCacheKeyHelpersInterface<S extends SupportedAlgorithmSuites> {
  buildEncryptionResponseCacheKey(
    partition: string,
    { suite, encryptionContext }: EncryptionRequest<S>
  ): Promise<string>
  buildDecryptionResponseCacheKey(
    partition: string,
    { suite, encryptedDataKeys, encryptionContext }: DecryptionRequest<S>
  ): Promise<string>
  encryptedDataKeysHash(encryptedDataKeys: ReadonlyArray<EncryptedDataKey>): Promise<Uint8Array[]>
  encryptionContextHash(context?: EncryptionContext): Promise<Uint8Array>
}
