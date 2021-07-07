// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Here I am reusing the Material implementation and interface from material-management.
 * This is because there are many security guarantees that this implementations offer
 * that map to the current implementation of raw AES keyrings.
 * The KeyringTrace is an unfortunate case because there is no mapping.
 * However the trade off seems worth it and the convolutions to make it work seem minimal.
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
  KeyringTrace,
  KeyringTraceFlag,
  needs,
  EncryptionContext,
} from '@aws-crypto/material-management'

import {
  WrappingSuiteIdentifier,
  RawAesWrappingSuiteIdentifier,
} from './raw_aes_algorithm_suite'

export class NodeRawAesMaterial
  implements Readonly<CryptographicMaterial<NodeRawAesMaterial>>
{
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (
    dataKey: Uint8Array | AwsEsdkKeyObject,
    trace: KeyringTrace
  ) => NodeRawAesMaterial
  getUnencryptedDataKey!: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey!: () => NodeRawAesMaterial
  hasUnencryptedDataKey!: boolean
  keyringTrace: KeyringTrace[] = []
  encryptionContext: EncryptionContext = Object.freeze({})
  constructor(suiteId: WrappingSuiteIdentifier) {
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
  hasValidKey() {
    return this.hasUnencryptedDataKey
  }
}
frozenClass(NodeRawAesMaterial)

export class WebCryptoRawAesMaterial
  implements
    Readonly<CryptographicMaterial<WebCryptoRawAesMaterial>>,
    Readonly<WebCryptoMaterial<WebCryptoRawAesMaterial>>
{
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (
    dataKey: Uint8Array | AwsEsdkKeyObject,
    trace: KeyringTrace
  ) => WebCryptoRawAesMaterial
  getUnencryptedDataKey!: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey!: () => WebCryptoRawAesMaterial
  hasUnencryptedDataKey!: boolean
  keyringTrace: KeyringTrace[] = []
  setCryptoKey!: (
    dataKey: AwsEsdkJsCryptoKey | MixedBackendCryptoKey,
    trace: KeyringTrace
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
  hasValidKey() {
    return this.hasUnencryptedDataKey && this.hasCryptoKey
  }
}
frozenClass(WebCryptoRawAesMaterial)
