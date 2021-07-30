// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This file contains information about particular algorithm suites used
 * within the encryption SDK.  In most cases, end-users don't need to
 * manipulate this structure, but it can occasionally be needed for more
 * advanced use cases, such as writing keyrings.
 *
 * These are the WebCrypto specific values the AWS Encryption SDK for JavaScript
 * Algorithm Suites.
 */

import {
  AlgorithmSuite,
  AlgorithmSuiteIdentifier,
  WebCryptoEncryption,
  WebCryptoHash,
  WebCryptoECDHCurve,
  AlgorithmSuiteTypeWebCrypto,
  MessageFormat,
  Commitment,
  AesGcm,
  AlgBasic,
  AlgKdf,
  AlgKdfSigned,
  AlgCommitted,
  AlgCommittedSigned,
} from './algorithm_suites'
import { needs } from './needs'

interface WebCryptoAesGcm extends AesGcm {
  encryption: WebCryptoEncryption
}

interface WebCryptoAlgBasic extends AlgBasic {
  encryption: WebCryptoEncryption
}

interface WebCryptoAlgKdf extends AlgKdf {
  encryption: WebCryptoEncryption
  kdfHash: WebCryptoHash
}

interface WebCryptoAlgKdfSigned extends AlgKdfSigned {
  encryption: WebCryptoEncryption
  kdfHash: WebCryptoHash
  signatureCurve: WebCryptoECDHCurve
  signatureHash: WebCryptoHash
}

interface WebCryptoAlgCommitted extends AlgCommitted {
  encryption: WebCryptoEncryption
  kdfHash: WebCryptoHash
  commitmentHash: WebCryptoHash
}

interface WebCryptoAlgCommittedSigned extends AlgCommittedSigned {
  encryption: WebCryptoEncryption
  kdfHash: WebCryptoHash
  signatureCurve: WebCryptoECDHCurve
  signatureHash: WebCryptoHash
}

type WebCryptoAlgUnion = Readonly<
  | WebCryptoAlgBasic
  | WebCryptoAlgKdf
  | WebCryptoAlgKdfSigned
  | WebCryptoAlgCommitted
  | WebCryptoAlgCommittedSigned
>

type WebCryptoAlgorithmSuiteValues = WebCryptoAesGcm &
  Partial<Omit<AlgBasic, keyof WebCryptoAesGcm>> &
  Partial<Omit<AlgKdf, keyof WebCryptoAesGcm>> &
  Partial<Omit<AlgKdfSigned, keyof WebCryptoAesGcm>> &
  Partial<Omit<AlgCommitted, keyof WebCryptoAesGcm>> &
  Partial<Omit<AlgCommittedSigned, keyof WebCryptoAesGcm>>

/* References to https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
 * These are the composed parameters for each algorithm suite specification for
 * for the WebCrypto environment.
 */
const webCryptoAlgAes128GcmIv12Tag16: WebCryptoAlgBasic = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
  messageFormat: MessageFormat.V1,
  encryption: 'AES-GCM',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false,
  commitment: 'NONE',
}
/* Web browsers do not support 192 bit key lengths at this time. */
const webCryptoAlgAes192GcmIv12Tag16: WebCryptoAlgBasic = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16,
  messageFormat: MessageFormat.V1,
  encryption: 'AES-GCM',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false,
  commitment: 'NONE',
}
const webCryptoAlgAes256GcmIv12Tag16: WebCryptoAlgBasic = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16,
  messageFormat: MessageFormat.V1,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false,
  commitment: 'NONE',
}
const webCryptoAlgAes128GcmIv12Tag16HkdfSha256: WebCryptoAlgKdf = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
  messageFormat: MessageFormat.V1,
  encryption: 'AES-GCM',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true,
  commitment: 'NONE',
}
/* Web browsers do not support 192 bit key lengths at this time. */
const webCryptoAlgAes192GcmIv12Tag16HkdfSha256: WebCryptoAlgKdf = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
  messageFormat: MessageFormat.V1,
  encryption: 'AES-GCM',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true,
  commitment: 'NONE',
}
const webCryptoAlgAes256GcmIv12Tag16HkdfSha256: WebCryptoAlgKdf = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
  messageFormat: MessageFormat.V1,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true,
  commitment: 'NONE',
}
const webCryptoAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256: WebCryptoAlgKdfSigned =
  {
    id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
    messageFormat: MessageFormat.V1,
    encryption: 'AES-GCM',
    keyLength: 128,
    ivLength: 12,
    tagLength: 128,
    kdf: 'HKDF',
    kdfHash: 'SHA-256',
    cacheSafe: true,
    signatureCurve: 'P-256',
    signatureHash: 'SHA-256',
    commitment: 'NONE',
  }
/* Web browsers do not support 192 bit key lengths at this time. */
const webCryptoAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384: WebCryptoAlgKdfSigned =
  {
    id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    messageFormat: MessageFormat.V1,
    encryption: 'AES-GCM',
    keyLength: 192,
    ivLength: 12,
    tagLength: 128,
    kdf: 'HKDF',
    kdfHash: 'SHA-384',
    cacheSafe: true,
    signatureCurve: 'P-384',
    signatureHash: 'SHA-384',
    commitment: 'NONE',
  }
const webCryptoAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384: WebCryptoAlgKdfSigned =
  {
    id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    messageFormat: MessageFormat.V1,
    encryption: 'AES-GCM',
    keyLength: 256,
    ivLength: 12,
    tagLength: 128,
    kdf: 'HKDF',
    kdfHash: 'SHA-384',
    cacheSafe: true,
    signatureCurve: 'P-384',
    signatureHash: 'SHA-384',
    commitment: 'NONE',
  }

const webCryptoAlgAes256GcmHkdfSha512Committing: WebCryptoAlgCommitted = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
  messageFormat: MessageFormat.V2,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-512',
  cacheSafe: true,
  commitment: 'KEY',
  commitmentHash: 'SHA-512',
  suiteDataLength: 32,
  commitmentLength: 256,
  saltLengthBytes: 32,
}

const webCryptoAlgAes256GcmHkdfSha512CommittingEcdsaP384: WebCryptoAlgCommittedSigned =
  {
    id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    messageFormat: MessageFormat.V2,
    encryption: 'AES-GCM',
    keyLength: 256,
    ivLength: 12,
    tagLength: 128,
    kdf: 'HKDF',
    kdfHash: 'SHA-512',
    cacheSafe: true,
    signatureCurve: 'P-384',
    signatureHash: 'SHA-384',
    commitment: 'KEY',
    commitmentHash: 'SHA-512',
    suiteDataLength: 32,
    commitmentLength: 256,
    saltLengthBytes: 32,
  }

type WebCryptoAlgorithms = Readonly<
  { [id in AlgorithmSuiteIdentifier]: WebCryptoAlgUnion }
>
const webCryptoAlgorithms: WebCryptoAlgorithms = Object.freeze({
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16]: Object.freeze(
    webCryptoAlgAes128GcmIv12Tag16
  ),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16]: Object.freeze(
    webCryptoAlgAes192GcmIv12Tag16
  ),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16]: Object.freeze(
    webCryptoAlgAes256GcmIv12Tag16
  ),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256]:
    Object.freeze(webCryptoAlgAes128GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256]:
    Object.freeze(webCryptoAlgAes192GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256]:
    Object.freeze(webCryptoAlgAes256GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256]:
    Object.freeze(webCryptoAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]:
    Object.freeze(webCryptoAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]:
    Object.freeze(webCryptoAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY]:
    Object.freeze(webCryptoAlgAes256GcmHkdfSha512Committing),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384]:
    Object.freeze(webCryptoAlgAes256GcmHkdfSha512CommittingEcdsaP384),
})

/* Web browsers do not support 192 bit key lengths at this time.
 * To maintain type compatibility and TypeScript happiness between Algorithm Suites
 * I need to have the same list of AlgorithmSuiteIdentifier.
 * This list is maintained here to make sure that the error message is helpful.
 */
type WebCryptoAlgorithmSuiteIdentifier = Exclude<
  Exclude<
    Exclude<
      AlgorithmSuiteIdentifier,
      AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16
    >,
    AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256
  >,
  AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
>
type SupportedWebCryptoAlgorithms = Readonly<
  { [id in WebCryptoAlgorithmSuiteIdentifier]: WebCryptoAlgUnion }
>
const supportedWebCryptoAlgorithms: SupportedWebCryptoAlgorithms =
  Object.freeze({
    [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16]: Object.freeze(
      webCryptoAlgAes128GcmIv12Tag16
    ),
    // [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16),
    [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16]: Object.freeze(
      webCryptoAlgAes256GcmIv12Tag16
    ),
    [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256]:
      Object.freeze(webCryptoAlgAes128GcmIv12Tag16HkdfSha256),
    // [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16HkdfSha256),
    [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256]:
      Object.freeze(webCryptoAlgAes256GcmIv12Tag16HkdfSha256),
    [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256]:
      Object.freeze(webCryptoAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256),
    // [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384),
    [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]:
      Object.freeze(webCryptoAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384),
    [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY]:
      Object.freeze(webCryptoAlgAes256GcmHkdfSha512Committing),
    [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384]:
      Object.freeze(webCryptoAlgAes256GcmHkdfSha512CommittingEcdsaP384),
  })

export class WebCryptoAlgorithmSuite
  extends AlgorithmSuite
  implements WebCryptoAlgorithmSuiteValues
{
  declare messageFormat: MessageFormat
  declare encryption: WebCryptoEncryption
  declare commitment: Commitment
  declare kdfHash?: WebCryptoHash
  declare signatureCurve?: WebCryptoECDHCurve
  declare signatureHash?: WebCryptoHash
  type: AlgorithmSuiteTypeWebCrypto = 'webCrypto'
  declare commitmentHash?: WebCryptoHash
  constructor(id: AlgorithmSuiteIdentifier) {
    super(webCryptoAlgorithms[id])
    /* Precondition: Browsers do not support 192 bit keys so the AlgorithmSuiteIdentifier is removed.
     * This is primarily an error in decrypt but this make it clear.
     * The error can manifest deep in the decrypt loop making it hard to debug.
     */
    needs(
      Object.prototype.hasOwnProperty.call(supportedWebCryptoAlgorithms, id),
      '192-bit AES keys are not supported'
    )
    Object.setPrototypeOf(this, WebCryptoAlgorithmSuite.prototype)
    Object.freeze(this)
  }
}

Object.freeze(WebCryptoAlgorithmSuite.prototype)
Object.freeze(WebCryptoAlgorithmSuite)
