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

import { Keyring } from './keyring'
import { MultiKeyring } from './multi_keyring'
import { NodeAlgorithmSuite } from './node_algorithms' // eslint-disable-line no-unused-vars
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms' // eslint-disable-line no-unused-vars
import { immutableClass } from './immutable_class'

export { AlgorithmSuiteIdentifier, AlgorithmSuiteName, AlgorithmSuite } from './algorithm_suites'
export { AlgorithmSuiteTypeNode, AlgorithmSuiteTypeWebCrypto } from './algorithm_suites'
export { NodeEncryption, WebCryptoEncryption } from './algorithm_suites'
export { NodeHash, WebCryptoHash, NodeECDHCurve, WebCryptoECDHCurve } from './algorithm_suites'
export { KDF, KeyLength, IvLength, TagLength } from './algorithm_suites'
export { RawAesWrappingSuiteIdentifier, WrappingSuiteIdentifier } from './algorithm_suites'

export { WebCryptoAlgorithmSuite } from './web_crypto_algorithms'
export { NodeAlgorithmSuite } from './node_algorithms'

export { Keyring } from './keyring'
export { KeyringTrace, KeyringTraceFlag } from './keyring_trace'
export { MultiKeyring } from './multi_keyring'
export { NodeMaterialsManager, WebCryptoMaterialsManager } from './materials_manager'

export { NodeEncryptionMaterial, NodeDecryptionMaterial, isValidCryptoKey, isCryptoKey, keyUsageForMaterial, subtleFunctionForMaterial } from './cryptographic_material'
export { WebCryptoEncryptionMaterial, WebCryptoDecryptionMaterial } from './cryptographic_material'
export { isEncryptionMaterial, isDecryptionMaterial } from './cryptographic_material'
export { SignatureKey, VerificationKey } from './signature_key'
export { EncryptedDataKey, IEncryptedDataKey } from './encrypted_data_key'

export { immutableBaseClass, immutableClass, frozenClass, readOnlyProperty } from './immutable_class'

export { needs } from './needs'

export * from './types'

export abstract class KeyringNode extends Keyring<NodeAlgorithmSuite> {}
immutableClass(KeyringNode)
export class MultiKeyringNode extends MultiKeyring<NodeAlgorithmSuite> {}
immutableClass(MultiKeyringNode)
export abstract class KeyringWebCrypto extends Keyring<WebCryptoAlgorithmSuite> {}
immutableClass(KeyringWebCrypto)
export class MultiKeyringWebCrypto extends MultiKeyring<WebCryptoAlgorithmSuite> {}
immutableClass(MultiKeyringWebCrypto)
