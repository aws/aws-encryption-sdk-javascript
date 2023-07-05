// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringClass,
  KmsKeyringInput,
  KMSConstructible,
  KmsClientSupplier,
  getClient,
  limitRegions,
  excludeRegions,
  cacheClients,
  AwsEsdkKMSInterface,
} from '@aws-crypto/kms-keyring'
import {
  immutableClass,
  KeyringNode,
  Newable,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'
import { KMS, KMSClientConfig } from '@aws-sdk/client-kms'
import { version } from './version'
const getKmsClient = getClient(KMS, {
  customUserAgent: `AwsEncryptionSdkJavascriptNodejs/${version}`,
})
const cacheKmsClients = cacheClients(getKmsClient)

export type KmsKeyringNodeInput = Partial<KmsKeyringInput<AwsEsdkKMSInterface>>
export type KMSNodeConstructible = KMSConstructible<KMS, KMSClientConfig>
export type KmsNodeClientSupplier = KmsClientSupplier<AwsEsdkKMSInterface>

export class KmsKeyringNode extends KmsKeyringClass<
  NodeAlgorithmSuite,
  AwsEsdkKMSInterface
>(KeyringNode as Newable<KeyringNode>) {
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
