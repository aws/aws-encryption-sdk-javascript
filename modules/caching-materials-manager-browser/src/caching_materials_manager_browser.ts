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
    const { partition = toUtf8(synchronousRandomValues(64)) } = input

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
