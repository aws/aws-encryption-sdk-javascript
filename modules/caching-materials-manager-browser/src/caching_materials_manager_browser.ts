// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CachingMaterialsManager,
  decorateProperties,
  getEncryptionMaterials,
  decryptMaterials,
  cacheEntryHasExceededLimits,
  buildCryptographicMaterialsCacheKeyHelpers,
  CryptographicMaterialsCache,
  CachingMaterialsManagerInput,
} from '@aws-crypto/cache-material'
import {
  WebCryptoMaterialsManager,
  WebCryptoDefaultCryptographicMaterialsManager,
  WebCryptoAlgorithmSuite,
  KeyringWebCrypto,
  WebCryptoGetEncryptionMaterials,
  WebCryptoGetDecryptMaterials,
} from '@aws-crypto/material-management-browser'
import { fromUtf8, toUtf8 } from '@aws-sdk/util-utf8-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'
import { synchronousRandomValues } from '@aws-crypto/web-crypto-backend'
import { sha512 } from './sha512'

const cacheKeyHelpers = buildCryptographicMaterialsCacheKeyHelpers(
  fromUtf8,
  toUtf8,
  sha512
)

export class WebCryptoCachingMaterialsManager
  implements CachingMaterialsManager<WebCryptoAlgorithmSuite>
{
  declare readonly _cache: CryptographicMaterialsCache<WebCryptoAlgorithmSuite>
  declare readonly _backingMaterialsManager: WebCryptoMaterialsManager
  declare readonly _partition: string
  declare readonly _maxBytesEncrypted: number
  declare readonly _maxMessagesEncrypted: number
  declare readonly _maxAge: number

  constructor(input: CachingMaterialsManagerInput<WebCryptoAlgorithmSuite>) {
    const backingMaterialsManager =
      input.backingMaterials instanceof KeyringWebCrypto
        ? new WebCryptoDefaultCryptographicMaterialsManager(
            input.backingMaterials
          )
        : (input.backingMaterials as WebCryptoDefaultCryptographicMaterialsManager)

    /* Precondition: A partition value must exist for WebCryptoCachingMaterialsManager.
     * The maximum hash function at this time is 512.
     * So I create 64 bytes of random data.
     */
    const { partition = toBase64(synchronousRandomValues(64)) } = input

    decorateProperties(this, {
      ...input,
      backingMaterialsManager,
      partition,
    })
  }

  getEncryptionMaterials: WebCryptoGetEncryptionMaterials =
    getEncryptionMaterials<WebCryptoAlgorithmSuite>(cacheKeyHelpers)
  decryptMaterials: WebCryptoGetDecryptMaterials =
    decryptMaterials<WebCryptoAlgorithmSuite>(cacheKeyHelpers)
  _cacheEntryHasExceededLimits =
    cacheEntryHasExceededLimits<WebCryptoAlgorithmSuite>()
}
