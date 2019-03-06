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
  KmsKeyringInput,
  KMSConstructible,
  KmsClientSupplier,
  getClient,
  limitRegions,
  excludeRegions,
  cacheClients
} from '@aws-crypto/kms-keyring'
import {
  NodeAlgorithmSuite,
  immutableClass
} from '@aws-crypto/material-management-node'
import {KMS, KMSConfiguration} from '@aws-sdk/client-kms-node'

export type KmsKeyringNodeInput = KmsKeyringInput<KMS>
export type KMSNodeConstructible = KMSConstructible<KMS, KMSConfiguration>
export type KmsNodeClientSupplier = KmsClientSupplier<KMS>

export class KmsKeyringNode extends KmsKeyring<NodeAlgorithmSuite, KMS> {
  constructor(input: KmsKeyringNodeInput){
    super(input)
  }
}
immutableClass(KmsKeyringNode)

export {getClient, limitRegions, excludeRegions, cacheClients}
