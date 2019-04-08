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

import {SupportedAlgorithmSuites, DecryptionRequest, EncryptionRequest, EncryptedDataKey, EncryptionContext} from '@aws-crypto/material-management'
import { serializeFactory, uInt16BE } from '@aws-crypto/serialize'

//  512 bits of 0 for padding between hashes in decryption materials cache ID generation.
const BIT_PAD_512 = Buffer.alloc(64)

export function build<S extends SupportedAlgorithmSuites>(
  fromUtf8: (input: string) => Uint8Array,
  sha512Hex: (...data: ((Uint8Array|string))[]) => Promise<string>
): Build<S> {
  const {
    serializeEncryptionContext,
    encodeEncryptionContext,
    serializeEncryptedDataKey
  } = serializeFactory(fromUtf8)

  return {
    buildEncryptionResponseCacheKey,
    buildDecryptionResponseCacheKey,
    encryptedDataKeysHash,
    encryptionContextHash
  }
  
  async function buildEncryptionResponseCacheKey(
    partition: string,
    {suite, encryptionContext}: EncryptionRequest<S>
  ) {
    const algorithmInfo = suite
      ? [Buffer.from([1]), uInt16BE(suite.id)]
      : [Buffer.alloc(0)] 
  
    return sha512Hex(
      await sha512Hex(partition),
      ...algorithmInfo,
      await encryptionContextHash(encryptionContext)
    )
  }
  
  async function buildDecryptionResponseCacheKey(
    partition: string,
    {suite, encryptedDataKeys, encryptionContext}: DecryptionRequest<S>
  ) {
    const { id } = suite
  
    return sha512Hex(
      await sha512Hex(partition),
      uInt16BE(id),
      ...(await encryptedDataKeysHash(encryptedDataKeys)),
      BIT_PAD_512,
      await encryptionContextHash(encryptionContext)
    )
  }
  
  async function encryptedDataKeysHash(encryptedDataKeys: ReadonlyArray<EncryptedDataKey>) {
    const hashes = await Promise.all(
      encryptedDataKeys
        .map(serializeEncryptedDataKey)
        .map(edk => sha512Hex(edk))
      )
    return hashes
      // is this sort valid?  locally, it should be fine
      .sort((a, b) => a.localeCompare(b))
  }
  
  function encryptionContextHash(context?: EncryptionContext) {
    const encodedContext = encodeEncryptionContext(context || {})
    const serializedContext = serializeEncryptionContext(encodedContext)
    return sha512Hex(serializedContext)
  }
}

export interface Build<S extends SupportedAlgorithmSuites> {
  buildEncryptionResponseCacheKey(
    partition: string,
    {suite, encryptionContext}: EncryptionRequest<S>
  ): Promise<string>
  buildDecryptionResponseCacheKey(
    partition: string,
    {suite, encryptedDataKeys, encryptionContext}: DecryptionRequest<S>
  ): Promise<string>
  encryptedDataKeysHash(encryptedDataKeys: ReadonlyArray<EncryptedDataKey>): Promise<string[]>
  encryptionContextHash(context?: EncryptionContext): Promise<string>
}
