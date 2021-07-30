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
  AlgorithmSuite,
  AlgorithmSuiteIdentifier,
  NodeEncryption,
  NodeHash,
  NodeECDHCurve,
  AlgorithmSuiteTypeNode,
  MessageFormat,
  Commitment,
  AesGcm,
  AlgBasic,
  AlgKdf,
  AlgKdfSigned,
  AlgCommitted,
  AlgCommittedSigned,
} from './algorithm_suites'

interface NodeAesGcm extends AesGcm {
  encryption: NodeEncryption
}

interface NodeAlgBasic extends AlgBasic {
  encryption: NodeEncryption
}

interface NodeAlgKdf extends AlgKdf {
  encryption: NodeEncryption
  kdfHash: NodeHash
}

interface NodeAlgKdfSigned extends AlgKdfSigned {
  encryption: NodeEncryption
  kdfHash: NodeHash
  signatureCurve: NodeECDHCurve
  signatureHash: NodeHash
}

interface NodeAlgCommitted extends AlgCommitted {
  encryption: NodeEncryption
  kdfHash: NodeHash
  commitmentHash: NodeHash
}

interface NodeAlgCommittedSigned extends AlgCommittedSigned {
  encryption: NodeEncryption
  kdfHash: NodeHash
  signatureCurve: NodeECDHCurve
  signatureHash: NodeHash
}

type NodeAlgUnion = Readonly<
  | NodeAlgBasic
  | NodeAlgKdf
  | NodeAlgKdfSigned
  | NodeAlgCommitted
  | NodeAlgCommittedSigned
>

type NodeAlgorithmSuiteValues = NodeAesGcm &
  Partial<Omit<AlgBasic, keyof NodeAesGcm>> &
  Partial<Omit<AlgKdf, keyof NodeAesGcm>> &
  Partial<Omit<AlgKdfSigned, keyof NodeAesGcm>> &
  Partial<Omit<AlgCommitted, keyof NodeAesGcm>> &
  Partial<Omit<AlgCommittedSigned, keyof NodeAesGcm>>

/* References to https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
 * These are the composed parameters for each algorithm suite specification for
 * for the WebCrypto environment.
 */

const nodeAlgAes128GcmIv12Tag16: NodeAlgBasic = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-128-gcm',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false,
  commitment: 'NONE',
}
const nodeAlgAes192GcmIv12Tag16: NodeAlgBasic = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-192-gcm',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false,
  commitment: 'NONE',
}
const nodeAlgAes256GcmIv12Tag16: NodeAlgBasic = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-256-gcm',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false,
  commitment: 'NONE',
}
const nodeAlgAes128GcmIv12Tag16HkdfSha256: NodeAlgKdf = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-128-gcm',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha256',
  cacheSafe: true,
  commitment: 'NONE',
}
const nodeAlgAes192GcmIv12Tag16HkdfSha256: NodeAlgKdf = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-192-gcm',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha256',
  cacheSafe: true,
  commitment: 'NONE',
}
const nodeAlgAes256GcmIv12Tag16HkdfSha256: NodeAlgKdf = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-256-gcm',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha256',
  cacheSafe: true,
  commitment: 'NONE',
}
const nodeAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256: NodeAlgKdfSigned = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-128-gcm',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha256',
  cacheSafe: true,
  signatureCurve: 'prime256v1',
  signatureHash: 'sha256',
  commitment: 'NONE',
}
const nodeAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384: NodeAlgKdfSigned = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-192-gcm',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha384',
  cacheSafe: true,
  signatureCurve: 'secp384r1',
  signatureHash: 'sha384',
  commitment: 'NONE',
}
const nodeAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384: NodeAlgKdfSigned = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  messageFormat: MessageFormat.V1,
  encryption: 'aes-256-gcm',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha384',
  cacheSafe: true,
  signatureCurve: 'secp384r1',
  signatureHash: 'sha384',
  commitment: 'NONE',
}

const nodeAlgAes256GcmHkdfSha512Committing: NodeAlgCommitted = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
  messageFormat: MessageFormat.V2,
  encryption: 'aes-256-gcm',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha512',
  cacheSafe: true,
  commitment: 'KEY',
  commitmentHash: 'sha512',
  suiteDataLength: 32,
  commitmentLength: 256,
  saltLengthBytes: 32,
}

const nodeAlgAes256GcmHkdfSha512CommittingEcdsaP384: NodeAlgCommittedSigned = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
  messageFormat: MessageFormat.V2,
  encryption: 'aes-256-gcm',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'sha512',
  cacheSafe: true,
  signatureCurve: 'secp384r1',
  signatureHash: 'sha384',
  commitment: 'KEY',
  commitmentHash: 'sha512',
  suiteDataLength: 32,
  commitmentLength: 256,
  saltLengthBytes: 32,
}

type NodeAlgorithms = Readonly<
  { [id in AlgorithmSuiteIdentifier]: NodeAlgUnion }
>
const nodeAlgorithms: NodeAlgorithms = Object.freeze({
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16]: Object.freeze(
    nodeAlgAes128GcmIv12Tag16
  ),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16]: Object.freeze(
    nodeAlgAes192GcmIv12Tag16
  ),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16]: Object.freeze(
    nodeAlgAes256GcmIv12Tag16
  ),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256]:
    Object.freeze(nodeAlgAes128GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256]:
    Object.freeze(nodeAlgAes192GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256]:
    Object.freeze(nodeAlgAes256GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256]:
    Object.freeze(nodeAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]:
    Object.freeze(nodeAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]:
    Object.freeze(nodeAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY]:
    Object.freeze(nodeAlgAes256GcmHkdfSha512Committing),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384]:
    Object.freeze(nodeAlgAes256GcmHkdfSha512CommittingEcdsaP384),
})

export class NodeAlgorithmSuite
  extends AlgorithmSuite
  implements NodeAlgorithmSuiteValues
{
  declare messageFormat: MessageFormat
  declare encryption: NodeEncryption
  declare commitment: Commitment
  declare kdfHash?: NodeHash
  declare signatureCurve?: NodeECDHCurve
  declare signatureHash?: NodeHash
  type: AlgorithmSuiteTypeNode = 'node'
  declare commitmentHash?: NodeHash
  constructor(id: AlgorithmSuiteIdentifier) {
    super(nodeAlgorithms[id])
    Object.setPrototypeOf(this, NodeAlgorithmSuite.prototype)
    Object.freeze(this)
  }
}

Object.freeze(NodeAlgorithmSuite.prototype)
Object.freeze(NodeAlgorithmSuite)
