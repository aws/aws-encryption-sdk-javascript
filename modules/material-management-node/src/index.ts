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
  NodeAlgorithmSuite, // eslint-disable-line no-unused-vars
  Keyring, MultiKeyring, immutableClass
} from '@aws-crypto/material-management'

export * from './node_cryptographic_materials_manager'
export { getEncryptHelper, getDecryptionHelper } from './material_helpers'
export {
  NodeDecryptionMaterial, NodeEncryptionMaterial, NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier, EncryptionContext, EncryptedDataKey,
  KeyringTrace, KeyringTraceFlag, needs,
  immutableBaseClass, immutableClass, frozenClass, readOnlyProperty
} from '@aws-crypto/material-management'

export abstract class NodeKeyring extends Keyring<NodeAlgorithmSuite> {}
export abstract class NodeMultiKeyring extends MultiKeyring<NodeAlgorithmSuite> {}
immutableClass(NodeKeyring)
immutableClass(NodeMultiKeyring)
