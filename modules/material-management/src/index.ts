// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export { AlgorithmSuiteIdentifier, AlgorithmSuiteName, AlgorithmSuite } from './algorithm_suites'
export { AlgorithmSuiteTypeNode, AlgorithmSuiteTypeWebCrypto } from './algorithm_suites'
export { NodeEncryption, WebCryptoEncryption } from './algorithm_suites'
export { NodeHash, WebCryptoHash, NodeECDHCurve, WebCryptoECDHCurve } from './algorithm_suites'
export { KDF, KeyLength, IvLength, TagLength } from './algorithm_suites'

export { WebCryptoAlgorithmSuite } from './web_crypto_algorithms'
export { NodeAlgorithmSuite } from './node_algorithms'

export { Keyring, KeyringNode, KeyringWebCrypto } from './keyring'
export { KeyringTrace, KeyringTraceFlag } from './keyring_trace'
export { MultiKeyringNode, MultiKeyringWebCrypto } from './multi_keyring'
export * from './materials_manager'

export { NodeEncryptionMaterial, NodeDecryptionMaterial } from './cryptographic_material'
export { isValidCryptoKey, isCryptoKey, keyUsageForMaterial, subtleFunctionForMaterial } from './cryptographic_material'
export { WebCryptoEncryptionMaterial, WebCryptoDecryptionMaterial } from './cryptographic_material'
export { isEncryptionMaterial, isDecryptionMaterial } from './cryptographic_material'
export { unwrapDataKey, wrapWithKeyObjectIfSupported } from './cryptographic_material'
export { CryptographicMaterial, decorateCryptographicMaterial, decorateWebCryptoMaterial, WebCryptoMaterial } from './cryptographic_material'
export { SignatureKey, VerificationKey } from './signature_key'
export { EncryptedDataKey, IEncryptedDataKey } from './encrypted_data_key'

export { immutableBaseClass, immutableClass, frozenClass, readOnlyProperty } from './immutable_class'

export { needs } from './needs'
export { cloneMaterial } from './clone_cryptographic_material'

export * from './types'
