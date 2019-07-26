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

/* Here I am reusing the Material implementation and interface from material-management.
 * This is because there are many security guarantees that this implementations offer
 * that map to the current implementation of raw AES keyrings.
 * The KeyringTrace is an unfortunate case because there is no mapping.
 * However the trade off seems worth it and the convolutions to make it work seem minimal.
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
  AwsEsdkJsCryptoKey, // eslint-disable-line no-unused-vars
  AwsEsdkJsKeyUsage, // eslint-disable-line no-unused-vars
  KeyringTrace, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  needs,
  EncryptionContext // eslint-disable-line no-unused-vars
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
  encryptionContext: EncryptionContext = Object.freeze({})
  constructor (suiteId: WrappingSuiteIdentifier) {
    /* Precondition: NodeRawAesMaterial suiteId must be RawAesWrappingSuiteIdentifier. */
    needs(RawAesWrappingSuiteIdentifier[suiteId], 'suiteId not supported.')
    this.suite = new NodeAlgorithmSuite(suiteId)
    /* NodeRawAesMaterial need to set a flag, this is an abuse of TraceFlags
     * because the material is not generated.
     * but CryptographicMaterial force a flag to be set.
     */
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
  setCryptoKey!: (dataKey: AwsEsdkJsCryptoKey|MixedBackendCryptoKey, trace: KeyringTrace) => WebCryptoRawAesMaterial
  getCryptoKey!: () => AwsEsdkJsCryptoKey|MixedBackendCryptoKey
  hasCryptoKey!: boolean
  validUsages: ReadonlyArray<AwsEsdkJsKeyUsage>
  encryptionContext: EncryptionContext = Object.freeze({})
  constructor (suiteId: WrappingSuiteIdentifier) {
    /* Precondition: WebCryptoAlgorithmSuite suiteId must be RawAesWrappingSuiteIdentifier. */
    needs(RawAesWrappingSuiteIdentifier[suiteId], 'suiteId not supported.')
    this.suite = new WebCryptoAlgorithmSuite(suiteId)
    this.validUsages = Object.freeze([<AwsEsdkJsKeyUsage>'decrypt', <AwsEsdkJsKeyUsage>'encrypt'])
    /* WebCryptoRawAesMaterial need to set a flag, this is an abuse of TraceFlags
     * because the material is not generated.
     * but CryptographicMaterial force a flag to be set.
     */
    const setFlag = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    decorateCryptographicMaterial<WebCryptoRawAesMaterial>(this, setFlag)
    decorateWebCryptoMaterial<WebCryptoRawAesMaterial>(this, setFlag)
    Object.setPrototypeOf(this, WebCryptoRawAesMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey () {
    return this.hasUnencryptedDataKey && this.hasCryptoKey
  }
}
frozenClass(WebCryptoRawAesMaterial)
