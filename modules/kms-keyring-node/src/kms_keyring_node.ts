// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringClass,
  KeyRingConstructible,
  KmsKeyringInput,
  KMSConstructible,
  KmsClientSupplier,
  getClient,
  limitRegions,
  excludeRegions,
  cacheClients,
} from '@aws-crypto/kms-keyring'
import {
  NodeAlgorithmSuite,
  immutableClass,
  KeyringNode,
} from '@aws-crypto/material-management-node'
import { KMS } from 'aws-sdk'
const getKmsClient = getClient(KMS, {
  customUserAgent: 'AwsEncryptionSdkJavascriptNodejs/1.9.0',
})
const cacheKmsClients = cacheClients(getKmsClient)

export type KmsKeyringNodeInput = Partial<KmsKeyringInput<KMS>>
export type KMSNodeConstructible = KMSConstructible<
  KMS,
  KMS.ClientConfiguration
>
export type KmsNodeClientSupplier = KmsClientSupplier<KMS>

export class KmsKeyringNode extends KmsKeyringClass(
  KeyringNode as KeyRingConstructible<NodeAlgorithmSuite>
) {
  constructor({
    clientProvider = cacheKmsClients,
    keyIds,
    generatorKeyId,
    grantTokens,
    discovery,
  }: KmsKeyringNodeInput = {}) {
    super({ clientProvider, keyIds, generatorKeyId, grantTokens, discovery })
  }
}
immutableClass(KmsKeyringNode)

export {
  getKmsClient,
  cacheKmsClients,
  getClient,
  limitRegions,
  excludeRegions,
  cacheClients,
  KMS,
}
