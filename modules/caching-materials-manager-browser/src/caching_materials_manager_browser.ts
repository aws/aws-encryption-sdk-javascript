// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CachingMaterialsManager, // eslint-disable-line no-unused-vars
  decorateProperties,
  getEncryptionMaterials,
  decryptMaterials,
  cacheEntryHasExceededLimits,
  buildCryptographicMaterialsCacheKeyHelpers,
  CachingMaterialsManagerInput, // eslint-disable-line no-unused-vars
  CryptographicMaterialsCache // eslint-disable-line no-unused-vars
} from '@aws-crypto/cache-material'
import {
  WebCryptoMaterialsManager, // eslint-disable-line no-unused-vars
  WebCryptoDefaultCryptographicMaterialsManager,
  WebCryptoAlgorithmSuite, // eslint-disable-line no-unused-vars
  KeyringWebCrypto,
  WebCryptoGetEncryptionMaterials, // eslint-disable-line no-unused-vars
  WebCryptoGetDecryptMaterials // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'
import { fromUtf8, toUtf8 } from '@aws-sdk/util-utf8-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'
import { synchronousRandomValues } from '@aws-crypto/web-crypto-backend'
import { sha512 } from './sha512'

const cacheKeyHelpers = buildCryptographicMaterialsCacheKeyHelpers(fromUtf8, toUtf8, sha512)

export class WebCryptoCachingMaterialsManager implements CachingMaterialsManager<WebCryptoAlgorithmSuite> {
  readonly _cache!: CryptographicMaterialsCache<WebCryptoAlgorithmSuite>
  readonly _backingMaterialsManager!: WebCryptoMaterialsManager
  readonly _partition!: string
  readonly _maxBytesEncrypted!: number
  readonly _maxMessagesEncrypted!: number
  readonly _maxAge!: number

  constructor (input: CachingMaterialsManagerInput<WebCryptoAlgorithmSuite>) {
    const backingMaterialsManager = input.backingMaterials instanceof KeyringWebCrypto
      ? new WebCryptoDefaultCryptographicMaterialsManager(input.backingMaterials)
      : <WebCryptoDefaultCryptographicMaterialsManager>input.backingMaterials

    /* Precondition: A partition value must exist for WebCryptoCachingMaterialsManager.
     * The maximum hash function at this time is 512.
     * So I create 64 bytes of random data.
     */
    const { partition = toBase64(synchronousRandomValues(64)) } = input

    decorateProperties(this, {
      ...input,
      backingMaterialsManager,
      partition
    })
  }

  getEncryptionMaterials: WebCryptoGetEncryptionMaterials = getEncryptionMaterials<WebCryptoAlgorithmSuite>(cacheKeyHelpers)
  decryptMaterials: WebCryptoGetDecryptMaterials = decryptMaterials<WebCryptoAlgorithmSuite>(cacheKeyHelpers)
  _cacheEntryHasExceededLimits = cacheEntryHasExceededLimits<WebCryptoAlgorithmSuite>()
}
