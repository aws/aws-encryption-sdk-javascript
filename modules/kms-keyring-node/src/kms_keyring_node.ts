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
const getKmsClient = getClient(KMS)
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

export { getKmsClient, cacheKmsClients, limitRegions, excludeRegions, cacheClients }
