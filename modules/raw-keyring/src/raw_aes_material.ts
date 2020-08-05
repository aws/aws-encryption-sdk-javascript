// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Here I am reusing the Material implementation and interface from material-management.
 * This is because there are many security guarantees that this implementations offer
 * that map to the current implementation of raw AES keyrings.
 */

import {
  CryptographicMaterial,
  WebCryptoMaterial,
  MixedBackendCryptoKey,
  decorateCryptographicMaterial,
  decorateWebCryptoMaterial,
  frozenClass,
  NodeAlgorithmSuite,
  WebCryptoAlgorithmSuite,
  AwsEsdkJsCryptoKey,
  AwsEsdkJsKeyUsage,
  AwsEsdkKeyObject,
  needs,
  EncryptionContext,
} from '@aws-crypto/material-management'

import {
  WrappingSuiteIdentifier,
  RawAesWrappingSuiteIdentifier,
} from './raw_aes_algorithm_suite'

export class NodeRawAesMaterial
  implements Readonly<CryptographicMaterial<NodeRawAesMaterial>> {
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (
    dataKey: Uint8Array | AwsEsdkKeyObject
  ) => NodeRawAesMaterial
  getUnencryptedDataKey!: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey!: () => NodeRawAesMaterial
  hasUnencryptedDataKey!: boolean
  encryptionContext: EncryptionContext = Object.freeze({})
  constructor(suiteId: WrappingSuiteIdentifier) {
    /* Precondition: NodeRawAesMaterial suiteId must be RawAesWrappingSuiteIdentifier. */
    needs(RawAesWrappingSuiteIdentifier[suiteId], 'suiteId not supported.')
    this.suite = new NodeAlgorithmSuite(suiteId)
    decorateCryptographicMaterial<NodeRawAesMaterial>(this)
    Object.setPrototypeOf(this, NodeRawAesMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey() {
    return this.hasUnencryptedDataKey
  }
}
frozenClass(NodeRawAesMaterial)

export class WebCryptoRawAesMaterial
  implements
    Readonly<CryptographicMaterial<WebCryptoRawAesMaterial>>,
    Readonly<WebCryptoMaterial<WebCryptoRawAesMaterial>> {
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (
    dataKey: Uint8Array | AwsEsdkKeyObject
  ) => WebCryptoRawAesMaterial
  getUnencryptedDataKey!: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey!: () => WebCryptoRawAesMaterial
  hasUnencryptedDataKey!: boolean
  setCryptoKey!: (
    dataKey: AwsEsdkJsCryptoKey | MixedBackendCryptoKey
  ) => WebCryptoRawAesMaterial
  getCryptoKey!: () => AwsEsdkJsCryptoKey | MixedBackendCryptoKey
  hasCryptoKey!: boolean
  validUsages: ReadonlyArray<AwsEsdkJsKeyUsage>
  encryptionContext: EncryptionContext = Object.freeze({})
  constructor(suiteId: WrappingSuiteIdentifier) {
    /* Precondition: WebCryptoAlgorithmSuite suiteId must be RawAesWrappingSuiteIdentifier. */
    needs(RawAesWrappingSuiteIdentifier[suiteId], 'suiteId not supported.')
    this.suite = new WebCryptoAlgorithmSuite(suiteId)
    this.validUsages = Object.freeze([
      'decrypt',
      'encrypt',
    ] as AwsEsdkJsKeyUsage[])
    decorateCryptographicMaterial<WebCryptoRawAesMaterial>(this)
    decorateWebCryptoMaterial<WebCryptoRawAesMaterial>(this)
    Object.setPrototypeOf(this, WebCryptoRawAesMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey() {
    return this.hasUnencryptedDataKey && this.hasCryptoKey
  }
}
frozenClass(WebCryptoRawAesMaterial)
