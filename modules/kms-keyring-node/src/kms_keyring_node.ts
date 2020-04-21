// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringClass,
  KeyRingConstructible, // eslint-disable-line no-unused-vars
  KmsKeyringInput, // eslint-disable-line no-unused-vars
  KMSConstructible, // eslint-disable-line no-unused-vars
  KmsClientSupplier, // eslint-disable-line no-unused-vars
  getClient,
  limitRegions,
  excludeRegions,
  cacheClients
} from '@aws-crypto/kms-keyring'
import {
  NodeAlgorithmSuite, // eslint-disable-line no-unused-vars
  immutableClass, KeyringNode
} from '@aws-crypto/material-management-node'
import { KMS } from 'aws-sdk' // eslint-disable-line no-unused-vars
const getKmsClient = getClient(KMS, { customUserAgent: 'AwsEncryptionSdkJavascriptNodejs' })
const cacheKmsClients = cacheClients(getKmsClient)

export type KmsKeyringNodeInput = Partial<KmsKeyringInput<KMS>>
export type KMSNodeConstructible = KMSConstructible<KMS, KMS.ClientConfiguration>
export type KmsNodeClientSupplier = KmsClientSupplier<KMS>

export class KmsKeyringNode extends KmsKeyringClass(KeyringNode as KeyRingConstructible<NodeAlgorithmSuite>) {
  constructor ({
    clientProvider = cacheKmsClients,
    keyIds,
    generatorKeyId,
    grantTokens,
    discovery
  }: KmsKeyringNodeInput = {}) {
    super({ clientProvider, keyIds, generatorKeyId, grantTokens, discovery })
  }
}
immutableClass(KmsKeyringNode)

export { getKmsClient, cacheKmsClients, getClient, limitRegions, excludeRegions, cacheClients, KMS }
