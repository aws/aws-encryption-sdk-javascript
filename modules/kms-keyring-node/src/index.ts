/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
  KmsKeyring,
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
  immutableClass
} from '@aws-crypto/material-management-node'
import { KMS, KMSConfiguration } from '@aws-sdk/client-kms-node' // eslint-disable-line no-unused-vars
const getKmsClient = getClient(KMS)

export type KmsKeyringNodeInput = KmsKeyringInput<KMS>
export type KMSNodeConstructible = KMSConstructible<KMS, KMSConfiguration>
export type KmsNodeClientSupplier = KmsClientSupplier<KMS>

export class KmsKeyringNode extends KmsKeyring<NodeAlgorithmSuite, KMS> {
  constructor({
    clientProvider = getKmsClient,
    kmsKeys,
    generatorKmsKey,
    grantTokens
  }) {
    super({clientProvider, kmsKeys, generatorKmsKey, grantTokens})
  }
}
immutableClass(KmsKeyringNode)

export { getKmsClient, limitRegions, excludeRegions, cacheClients }
