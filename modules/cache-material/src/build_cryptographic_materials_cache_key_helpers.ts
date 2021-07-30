// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SupportedAlgorithmSuites,
  DecryptionRequest,
  EncryptionRequest,
  EncryptedDataKey,
  EncryptionContext,
} from '@aws-crypto/material-management'
import { serializeFactory, uInt16BE } from '@aws-crypto/serialize'
import { compare } from './portable_compare'

//  512 bits of 0 for padding between hashes in decryption materials cache ID generation.
const BIT_PAD_512 = Buffer.alloc(64)

export function buildCryptographicMaterialsCacheKeyHelpers<
  S extends SupportedAlgorithmSuites
>(
  fromUtf8: (input: string) => Uint8Array,
  toUtf8: (input: Uint8Array) => string,
  sha512: (...data: (Uint8Array | string)[]) => Promise<Uint8Array>
): CryptographicMaterialsCacheKeyHelpersInterface<S> {
  const { serializeEncryptionContext, serializeEncryptedDataKey } =
    serializeFactory(fromUtf8)

  return {
    buildEncryptionMaterialCacheKey,
    buildDecryptionMaterialCacheKey,
    encryptedDataKeysHash,
    encryptionContextHash,
  }

  async function buildEncryptionMaterialCacheKey(
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

  async function buildDecryptionMaterialCacheKey(
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

  async function encryptedDataKeysHash(
    encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
  ) {
    const hashes = await Promise.all(
      encryptedDataKeys
        .map(serializeEncryptedDataKey)
        .map(async (edk) => sha512(edk))
    )
    return hashes.sort(compare)
  }

  async function encryptionContextHash(context: EncryptionContext) {
    /* The AAD section is uInt16BE(length) + AAD
     * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
     * However, the RAW Keyring wants _only_ the ADD.
     * So, I just slice off the length.
     */
    const serializedContext = serializeEncryptionContext(context).slice(2)
    return sha512(serializedContext)
  }
}

export interface CryptographicMaterialsCacheKeyHelpersInterface<
  S extends SupportedAlgorithmSuites
> {
  buildEncryptionMaterialCacheKey(
    partition: string,
    { suite, encryptionContext }: Omit<EncryptionRequest<S>, 'commitmentPolicy'>
  ): Promise<string>
  buildDecryptionMaterialCacheKey(
    partition: string,
    { suite, encryptedDataKeys, encryptionContext }: DecryptionRequest<S>
  ): Promise<string>
  encryptedDataKeysHash(
    encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
  ): Promise<Uint8Array[]>
  encryptionContextHash(context: EncryptionContext): Promise<Uint8Array>
}
