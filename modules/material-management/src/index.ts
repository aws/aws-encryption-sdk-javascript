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

export { AlgorithmSuiteIdentifier, AlgorithmSuiteName, AlgorithmSuite } from './algorithm_suites'
export { AlgorithmSuiteTypeNode, AlgorithmSuiteTypeWebCrypto } from './algorithm_suites'
export { NodeEncryption, WebCryptoEncryption } from './algorithm_suites'
export { NodeHash, WebCryptoHash, NodeECDHCurve, WebCryptoECDHCurve } from './algorithm_suites'
export { KDF, KeyLength, IvLength, TagLength } from './algorithm_suites'
export { RawAesWrappingSuiteIdentifier, WrappingSuiteIdentifier } from './algorithm_suites'

export { WebCryptoAlgorithmSuite } from './web_crypto_algorithms'
export { NodeAlgorithmSuite } from './node_algorithms'

export { Keyring, KeyringNode, KeyringWebCrypto } from './keyring'
export { KeyringTrace, KeyringTraceFlag } from './keyring_trace'
export { MultiKeyringNode, MultiKeyringWebCrypto } from './multi_keyring'
export { NodeMaterialsManager, WebCryptoMaterialsManager } from './materials_manager'

export { NodeEncryptionMaterial, NodeDecryptionMaterial } from './cryptographic_material'
export { isValidCryptoKey, isCryptoKey, keyUsageForMaterial, subtleFunctionForMaterial } from './cryptographic_material'
export { WebCryptoEncryptionMaterial, WebCryptoDecryptionMaterial } from './cryptographic_material'
export { isEncryptionMaterial, isDecryptionMaterial } from './cryptographic_material'
export { SignatureKey, VerificationKey } from './signature_key'
export { EncryptedDataKey, IEncryptedDataKey } from './encrypted_data_key'

export { immutableBaseClass, immutableClass, frozenClass, readOnlyProperty } from './immutable_class'

export { needs } from './needs'

export * from './types'
