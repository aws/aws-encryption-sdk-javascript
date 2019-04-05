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
  CryptographicMaterial, // eslint-disable-line no-unused-vars
  WebCryptoMaterial, // eslint-disable-line no-unused-vars
  MixedBackendCryptoKey, // eslint-disable-line no-unused-vars
  decorateCryptographicMaterial,
  decorateWebCryptoMaterial,
  frozenClass,
  NodeAlgorithmSuite,
  WebCryptoAlgorithmSuite,
  KeyringTrace, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  needs
} from '@aws-crypto/material-management'

import {
  WrappingSuiteIdentifier, // eslint-disable-line no-unused-vars
  RawAesWrappingSuiteIdentifier
} from './raw_aes_algorithm_suite'

export class NodeRawAesMaterial implements
  Readonly<CryptographicMaterial<NodeRawAesMaterial>> {
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array, trace: KeyringTrace) => NodeRawAesMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => NodeRawAesMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  constructor (suiteId: WrappingSuiteIdentifier) {
    /* Precondition: NodeRawAesMaterial suiteId must be RawAesWrappingSuiteIdentifier. */
    needs(RawAesWrappingSuiteIdentifier[suiteId], 'suiteId not supported.')
    this.suite = new NodeAlgorithmSuite(suiteId)
    // // EncryptionMaterial have generated a data key on setUnencryptedDataKey
    const setFlags = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    decorateCryptographicMaterial<NodeRawAesMaterial>(this, setFlags)
    Object.setPrototypeOf(this, NodeRawAesMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey () {
    return this.hasUnencryptedDataKey
  }
}
frozenClass(NodeRawAesMaterial)

export class WebCryptoRawAesMaterial implements
  Readonly<CryptographicMaterial<WebCryptoRawAesMaterial>>,
  Readonly<WebCryptoMaterial<WebCryptoRawAesMaterial>> {
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array, trace: KeyringTrace) => WebCryptoRawAesMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => WebCryptoRawAesMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  setCryptoKey!: (dataKey: CryptoKey|MixedBackendCryptoKey, trace: KeyringTrace) => WebCryptoRawAesMaterial
  getCryptoKey!: () => CryptoKey|MixedBackendCryptoKey
  hasCryptoKey!: boolean
  constructor (suiteId: WrappingSuiteIdentifier) {
    /* Precondition: WebCryptoAlgorithmSuite suiteId must be RawAesWrappingSuiteIdentifier. */
    needs(RawAesWrappingSuiteIdentifier[suiteId], 'suiteId not supported.')
    this.suite = new WebCryptoAlgorithmSuite(suiteId)
    // // EncryptionMaterial have generated a data key on setUnencryptedDataKey
    const setFlag = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    decorateCryptographicMaterial<WebCryptoRawAesMaterial>(this, setFlag)
    decorateWebCryptoMaterial<WebCryptoRawAesMaterial>(this, 0)
    Object.setPrototypeOf(this, WebCryptoRawAesMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey () {
    return this.hasUnencryptedDataKey && this.hasCryptoKey
  }
}
frozenClass(WebCryptoRawAesMaterial)
