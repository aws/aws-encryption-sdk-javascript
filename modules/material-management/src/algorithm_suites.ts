// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This file contains information about particular algorithm suites used
 * within the encryption SDK.  In most cases, end-users don't need to
 * manipulate this structure, but it can occasionally be needed for more
 * advanced use cases, such as writing keyrings.
 *
 * Here we describe the overall shape of the Algorithm Suites used by the AWS Encryption
 * SDK for JavaScript.  Specific details for Node.js and WebCrypto can be found
 * in the respective files
 */

import { immutableClass, readOnlyProperty } from './immutable_class'
import { needs } from './needs'

/* References to https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
 * These define the possible parameters for algorithm specifications that correspond
 * to the Node.js or WebCrypto environment.
 * These parameters are composed into an algorithm suite specification for each
 * environment in the respective files.
 */
export enum AlgorithmSuiteIdentifier {
  'ALG_AES128_GCM_IV12_TAG16' = 0x0014,
  'ALG_AES192_GCM_IV12_TAG16' = 0x0046,
  'ALG_AES256_GCM_IV12_TAG16' = 0x0078,
  'ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256' = 0x0114,
  'ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256' = 0x0146,
  'ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256' = 0x0178,
  'ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256' = 0x0214,
  'ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384' = 0x0346,
  'ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384' = 0x0378,
  'ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY' = 0x0478,
  'ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384' = 0x0578,
}
Object.freeze(AlgorithmSuiteIdentifier)

export enum CommitmentPolicy {
  'FORBID_ENCRYPT_ALLOW_DECRYPT' = 'FORBID_ENCRYPT_ALLOW_DECRYPT',
  'REQUIRE_ENCRYPT_ALLOW_DECRYPT' = 'REQUIRE_ENCRYPT_ALLOW_DECRYPT',
  'REQUIRE_ENCRYPT_REQUIRE_DECRYPT' = 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
}
Object.freeze(CommitmentPolicy)

export enum SignaturePolicy {
  'ALLOW_ENCRYPT_ALLOW_DECRYPT' = 'ALLOW_ENCRYPT_ALLOW_DECRYPT',
  'ALLOW_ENCRYPT_FORBID_DECRYPT' = 'ALLOW_ENCRYPT_FORBID_DECRYPT',
}
Object.freeze(SignaturePolicy)

/* Typescript enums are useful, but tricky.
 * I have to use Declaration Merging
 * to make everything work.
 * First I pluck off the elements I do not want,
 * from AlgorithmSuiteIdentifier.
 * The rest param then includes "everything else".
 * I make sure to pull both the enum name and value,
 * because typescript enums compile to lookup in both directions.
 * This gives us the compile side of the enum.
 * It does *not* have the name or id of
 * any unsupported suites.
 * This means that on encrypt,
 * if a customer is passing a literal value,
 * if will fail the check.
 * e.g.
 * needs(!AlgorithmSuiteIdentifier[0x0014],
 *  'wait, this is not supported for encrypt')
 *
 * All this resolves the object
 * that is emitted by TypeScript.
 * But the "type side" still needs to work.
 * e.g.
 * const id: AlgorithmSuiteIdentifier = NonCommittingAlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
 * Otherwise when passing these values around
 * from the new enums they will not behave
 * like values in the parent enum.
 *
 */

export type NonSigningAlgorithmSuiteIdentifier = Exclude<
  AlgorithmSuiteIdentifier,
  | typeof AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
  | typeof AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
  | typeof AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
  | typeof AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
>

export const NonSigningAlgorithmSuiteIdentifier = (() => {
  const {
    ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
    ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    // Both the name side above, and the id side below
    [0x0214]: NAME_ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
    [0x0346]: NAME_ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    [0x0378]: NAME_ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    [0x0578]: NAME_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    ...NonSigningAlgorithmSuiteIdentifier
  } = AlgorithmSuiteIdentifier
  return NonSigningAlgorithmSuiteIdentifier
})()

export const SignaturePolicySuites = Object.freeze({
  isDecryptEnabled(
    signaturePolicy: SignaturePolicy,
    suite: AlgorithmSuiteIdentifier | AlgorithmSuite,
    messageId: string
  ): void {
    const id = (suite as AlgorithmSuite).id || suite
    const name = (suite as AlgorithmSuite).name || AlgorithmSuiteIdentifier[id]
    let decryption_client_name = 'decryptStream'
    let signature_description = 'signed'
    if (signaturePolicy === SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT) {
      decryption_client_name = 'decryptUnsignedMessageStream'
      signature_description = 'un-signed'
    }

    /* Precondition: Only handle DecryptionMaterial for algorithm suites supported in signaturePolicy. */
    needs(
      this[signaturePolicy].decryptEnabledSuites[id],
      `Configuration conflict. ` +
        `Cannot process message with ID ${messageId} ` +
        `due to client method ${decryption_client_name} ` +
        `requiring only ${signature_description} messages. ` +
        `Algorithm ID was ${name}. ` +
        `See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#digital-sigs`
    )
  },
  [SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT]: Object.freeze({
    decryptEnabledSuites: AlgorithmSuiteIdentifier,
    defaultAlgorithmSuite:
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
  }),
  [SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT]: Object.freeze({
    decryptEnabledSuites: NonSigningAlgorithmSuiteIdentifier,
    defaultAlgorithmSuite:
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
  }),
})

export type NonCommittingAlgorithmSuiteIdentifier = Exclude<
  AlgorithmSuiteIdentifier,
  | typeof AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
  | typeof AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
>

export const NonCommittingAlgorithmSuiteIdentifier = (() => {
  const {
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    // Both the name side above, and the id side below
    [0x0478]: NAME_ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
    [0x0578]: NAME_ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    ...NonCommittingAlgorithmSuiteIdentifier
  } = AlgorithmSuiteIdentifier
  return NonCommittingAlgorithmSuiteIdentifier
})()

export type CommittingAlgorithmSuiteIdentifier = Extract<
  AlgorithmSuiteIdentifier,
  | typeof AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
  | typeof AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
  | typeof AlgorithmSuiteIdentifier[0x0478]
  | typeof AlgorithmSuiteIdentifier[0x0578]
>

export const CommittingAlgorithmSuiteIdentifier = (() => {
  const {
    ALG_AES128_GCM_IV12_TAG16,
    ALG_AES192_GCM_IV12_TAG16,
    ALG_AES256_GCM_IV12_TAG16,
    ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
    ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
    ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
    ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    // Both the name side above, and the id side below
    [0x0014]: NAME_ALG_AES128_GCM_IV12_TAG16,
    [0x0046]: NAME_ALG_AES192_GCM_IV12_TAG16,
    [0x0078]: NAME_ALG_AES256_GCM_IV12_TAG16,
    [0x0114]: NAME_ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
    [0x0146]: NAME_ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
    [0x0178]: NAME_ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
    [0x0214]: NAME_ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
    [0x0346]: NAME_ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    [0x0378]: NAME_ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    ...CommittingAlgorithmSuiteIdentifier
  } = AlgorithmSuiteIdentifier
  return CommittingAlgorithmSuiteIdentifier
})()

export const CommitmentPolicySuites = Object.freeze({
  isEncryptEnabled(
    commitmentPolicy: CommitmentPolicy,
    suite?: AlgorithmSuiteIdentifier | AlgorithmSuite
  ) {
    if (!suite) return
    const id = (suite as AlgorithmSuite).id || suite
    const name = (suite as AlgorithmSuite).name || AlgorithmSuiteIdentifier[id]

    /* Precondition: Only handle EncryptionMaterial for algorithm suites supported in commitmentPolicy. */
    needs(
      this[commitmentPolicy].encryptEnabledSuites[id],
      `Configuration conflict. ` +
        `Cannot encrypt due to CommitmentPolicy ${commitmentPolicy} ` +
        `requiring only non-committed messages. ` +
        `Algorithm ID was ${name}. ` +
        `See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html`
    )
  },
  isDecryptEnabled(
    commitmentPolicy: CommitmentPolicy,
    suite: AlgorithmSuiteIdentifier | AlgorithmSuite,
    messageId: string
  ) {
    const id = (suite as AlgorithmSuite).id || suite
    const name = (suite as AlgorithmSuite).name || AlgorithmSuiteIdentifier[id]

    /* Precondition: Only handle DecryptionMaterial for algorithm suites supported in commitmentPolicy. */
    needs(
      this[commitmentPolicy].decryptEnabledSuites[id],
      `Configuration conflict. ` +
        `Cannot process message with ID ${messageId} ` +
        `due to CommitmentPolicy ${commitmentPolicy} ` +
        `requiring only committed messages. ` +
        `Algorithm ID was ${name}. ` +
        `See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html`
    )
  },
  [CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT]: Object.freeze({
    encryptEnabledSuites: NonCommittingAlgorithmSuiteIdentifier,
    decryptEnabledSuites: AlgorithmSuiteIdentifier,
    defaultAlgorithmSuite:
      NonCommittingAlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  }),
  [CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT]: Object.freeze({
    encryptEnabledSuites: CommittingAlgorithmSuiteIdentifier,
    decryptEnabledSuites: AlgorithmSuiteIdentifier,
    defaultAlgorithmSuite:
      CommittingAlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
  }),
  [CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT]: Object.freeze({
    encryptEnabledSuites: CommittingAlgorithmSuiteIdentifier,
    decryptEnabledSuites: CommittingAlgorithmSuiteIdentifier,
    defaultAlgorithmSuite:
      CommittingAlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
  }),
})

export type AlgorithmSuiteName = keyof typeof AlgorithmSuiteIdentifier
export type AlgorithmSuiteTypeNode = 'node'
export type AlgorithmSuiteTypeWebCrypto = 'webCrypto'
export type NodeEncryption = 'aes-128-gcm' | 'aes-192-gcm' | 'aes-256-gcm'
export type WebCryptoEncryption = 'AES-GCM'
export type KDF = 'HKDF'
export type Commitment = 'NONE' | 'KEY'
export type NodeHash = 'sha256' | 'sha384' | 'sha512'
export type WebCryptoHash = 'SHA-256' | 'SHA-384' | 'SHA-512'
export type NodeECDHCurve = 'prime256v1' | 'secp384r1'
export type WebCryptoECDHCurve = 'P-256' | 'P-384'
export type KeyLength = 128 | 192 | 256
export type CommitmentLength = 256
export type HKDFSaltLengthBytes = 32
export type IvLength = 12
export type TagLength = 128
export type SuiteDataLength = 32
export enum MessageFormat {
  V1 = 0x01,
  V2 = 0x02,
}
Object.freeze(MessageFormat)

export interface AesGcm {
  id: AlgorithmSuiteIdentifier
  messageFormat: MessageFormat
  encryption: NodeEncryption | WebCryptoEncryption
  keyLength: KeyLength
  ivLength: IvLength
  tagLength: TagLength
  cacheSafe: boolean
  kdf?: KDF
  commitment: Commitment
}
export interface AlgBasic extends AesGcm {
  messageFormat: MessageFormat.V1
  cacheSafe: false
  commitment: 'NONE'
}
export interface AlgKdf extends AesGcm {
  messageFormat: MessageFormat.V1
  cacheSafe: true
  kdf: 'HKDF'
  kdfHash: NodeHash | WebCryptoHash
  commitment: 'NONE'
}
export interface AlgKdfSigned extends AlgKdf {
  messageFormat: MessageFormat.V1
  signatureCurve: NodeECDHCurve | WebCryptoECDHCurve
  signatureHash: NodeHash | WebCryptoHash
}
export interface AlgCommitted extends AesGcm {
  messageFormat: MessageFormat.V2
  cacheSafe: true
  kdf: 'HKDF'
  kdfHash: NodeHash | WebCryptoHash
  commitment: 'KEY'
  suiteDataLength: SuiteDataLength
  commitmentHash: NodeHash | WebCryptoHash
  commitmentLength: CommitmentLength
  saltLengthBytes: HKDFSaltLengthBytes
}
export interface AlgCommittedSigned extends AlgCommitted {
  signatureCurve: NodeECDHCurve | WebCryptoECDHCurve
  signatureHash: NodeHash | WebCryptoHash
}

type AlgUnion =
  | AlgBasic
  | AlgKdf
  | AlgKdfSigned
  | AlgCommitted
  | AlgCommittedSigned

type AlgorithmSuiteValues = AesGcm &
  Partial<Omit<AlgBasic, keyof AesGcm>> &
  Partial<Omit<AlgKdf, keyof AesGcm>> &
  Partial<Omit<AlgKdfSigned, keyof AesGcm>> &
  Partial<Omit<AlgCommitted, keyof AesGcm>> &
  Partial<Omit<AlgCommittedSigned, keyof AesGcm>>

export abstract class AlgorithmSuite implements AlgorithmSuiteValues {
  declare id: AlgorithmSuiteIdentifier
  declare name: AlgorithmSuiteName
  declare messageFormat: MessageFormat
  declare encryption: NodeEncryption | WebCryptoEncryption
  declare keyLength: KeyLength
  declare keyLengthBytes: number
  declare ivLength: IvLength
  declare tagLength: TagLength
  declare cacheSafe: boolean
  declare kdf?: KDF
  declare kdfHash?: NodeHash | WebCryptoHash
  declare signatureCurve?: NodeECDHCurve | WebCryptoECDHCurve
  declare signatureHash?: NodeHash | WebCryptoHash
  declare type: AlgorithmSuiteTypeNode | AlgorithmSuiteTypeWebCrypto
  declare suiteDataLength?: SuiteDataLength
  declare commitmentHash?: NodeHash | WebCryptoHash
  declare commitmentLength?: CommitmentLength
  declare saltLengthBytes?: HKDFSaltLengthBytes
  declare commitment: Commitment
  constructor(suiteValues: AlgUnion) {
    needs(
      this.constructor !== AlgorithmSuite,
      'new AlgorithmSuite is not allowed'
    )
    /* Precondition: A algorithm suite specification must be passed. */
    needs(suiteValues, 'Algorithm specification not set.')
    /* Precondition: The Algorithm Suite Identifier must exist. */
    needs(
      AlgorithmSuiteIdentifier[suiteValues.id],
      'No suite by that identifier exists.'
    )
    Object.assign(this, suiteValues)

    readOnlyProperty(this, 'keyLengthBytes', this.keyLength / 8)
    readOnlyProperty(
      this,
      'name',
      AlgorithmSuiteIdentifier[this.id] as AlgorithmSuiteName
    )
  }
}
immutableClass(AlgorithmSuite)
