
// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This file contains information about particular algorithm suites used
 * within the encryption SDK.  In most cases, end-users don't need to
 * manipulate this structure, but it can occasionally be needed for more
 * advanced use cases, such as writing keyrings.
 *
 * These are the Node.js specific values the AWS Encryption SDK for JavaScript
 * Algorithm Suites.
 */

import {
  AlgorithmSuite, AlgorithmSuiteIdentifier,
  INodeAlgorithmSuite, NodeEncryption, NodeHash, NodeECDHCurve, AlgorithmSuiteTypeNode // eslint-disable-line no-unused-vars
} from './algorithm_suites'

/* References to https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
 * These are the composed parameters for each algorithm suite specification for
 * for the WebCrypto environment.
 */

const nodeAlgAes128GcmIv12Tag16: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
  encryption: 'aes-128-gcm',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
const nodeAlgAes192GcmIv12Tag16: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16,
  encryption: 'aes-192-gcm',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
const nodeAlgAes256GcmIv12Tag16: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16,
  encryption: 'aes-256-gcm',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
const nodeAlgAes128GcmIv12Tag16HkdfSha256: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'aes-128-gcm',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha256',
  cacheSafe: true
}
const nodeAlgAes192GcmIv12Tag16HkdfSha256: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'aes-192-gcm',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha256',
  cacheSafe: true
}
const nodeAlgAes256GcmIv12Tag16HkdfSha256: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'aes-256-gcm',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha256',
  cacheSafe: true
}
const nodeAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
  encryption: 'aes-128-gcm',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha256',
  cacheSafe: true,
  signatureCurve: 'prime256v1',
  signatureHash: 'sha256'
}
const nodeAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  encryption: 'aes-192-gcm',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha384',
  cacheSafe: true,
  signatureCurve: 'secp384r1',
  signatureHash: 'sha384'
}
const nodeAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384: INodeAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  encryption: 'aes-256-gcm',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha384',
  cacheSafe: true,
  signatureCurve: 'secp384r1',
  signatureHash: 'sha384'
}

type NodeAlgorithms = Readonly<{[id in AlgorithmSuiteIdentifier]: INodeAlgorithmSuite}>
const nodeAlgorithms: NodeAlgorithms = Object.freeze({
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16]: Object.freeze(nodeAlgAes128GcmIv12Tag16),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16]: Object.freeze(nodeAlgAes192GcmIv12Tag16),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16]: Object.freeze(nodeAlgAes256GcmIv12Tag16),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(nodeAlgAes128GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(nodeAlgAes192GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(nodeAlgAes256GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256]: Object.freeze(nodeAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(nodeAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(nodeAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384)
})

export class NodeAlgorithmSuite extends AlgorithmSuite implements INodeAlgorithmSuite {
  encryption!: NodeEncryption
  kdfHash?: NodeHash
  signatureCurve?: NodeECDHCurve
  signatureHash?: NodeHash
  type: AlgorithmSuiteTypeNode = 'node'
  constructor (id: AlgorithmSuiteIdentifier) {
    super(nodeAlgorithms[id])
    Object.setPrototypeOf(this, NodeAlgorithmSuite.prototype)
    Object.freeze(this)
  }
}

Object.freeze(NodeAlgorithmSuite.prototype)
Object.freeze(NodeAlgorithmSuite)
