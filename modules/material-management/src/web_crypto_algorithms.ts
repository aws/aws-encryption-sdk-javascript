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
  AlgorithmSuite, AlgorithmSuiteIdentifier,
  IWebCryptoAlgorithmSuite, WebCryptoEncryption, WebCryptoHash, // eslint-disable-line no-unused-vars
  WebCryptoECDHCurve, AlgorithmSuiteTypeWebCrypto // eslint-disable-line no-unused-vars
} from './algorithm_suites'
import { needs } from './needs'

/* References to https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
 * These are the composed parameters for each algorithm suite specification for
 * for the WebCrypto environment.
 */
const webCryptoAlgAes128GcmIv12Tag16: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
  encryption: 'AES-GCM',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
/* Web browsers do not support 192 bit key lengths at this time. */
const webCryptoAlgAes192GcmIv12Tag16: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16,
  encryption: 'AES-GCM',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
const webCryptoAlgAes256GcmIv12Tag16: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
const webCryptoAlgAes128GcmIv12Tag16HkdfSha256: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'AES-GCM',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true
}
/* Web browsers do not support 192 bit key lengths at this time. */
const webCryptoAlgAes192GcmIv12Tag16HkdfSha256: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'AES-GCM',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true
}
const webCryptoAlgAes256GcmIv12Tag16HkdfSha256: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true
}
const webCryptoAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
  encryption: 'AES-GCM',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true,
  signatureCurve: 'P-256',
  signatureHash: 'SHA-256'
}
/* Web browsers do not support 192 bit key lengths at this time. */
const webCryptoAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  encryption: 'AES-GCM',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-384',
  cacheSafe: true,
  signatureCurve: 'P-384',
  signatureHash: 'SHA-384'
}
const webCryptoAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-384',
  cacheSafe: true,
  signatureCurve: 'P-384',
  signatureHash: 'SHA-384'
}

type WebCryptoAlgorithms = Readonly<{[id in AlgorithmSuiteIdentifier]: IWebCryptoAlgorithmSuite}>
const webCryptoAlgorithms: WebCryptoAlgorithms = Object.freeze({
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16]: Object.freeze(webCryptoAlgAes128GcmIv12Tag16),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16]: Object.freeze(webCryptoAlgAes256GcmIv12Tag16),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(webCryptoAlgAes128GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(webCryptoAlgAes256GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256]: Object.freeze(webCryptoAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(webCryptoAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384)
})

/* Web browsers do not support 192 bit key lengths at this time.
 * To maintain type compatibility and TypeScript happiness between Algorithm Suites
 * I need to have the same list of AlgorithmSuiteIdentifier.
 * This list is maintained here to make sure that the error message is helpful.
 */
type WebCryptoAlgorithmSuiteIdentifier = Exclude<Exclude<Exclude<AlgorithmSuiteIdentifier,
  AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16>,
  AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256>,
  AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384>
type SupportedWebCryptoAlgorithms = Readonly<{[id in WebCryptoAlgorithmSuiteIdentifier]: IWebCryptoAlgorithmSuite}>
const supportedWebCryptoAlgorithms: SupportedWebCryptoAlgorithms = Object.freeze({
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16]: Object.freeze(webCryptoAlgAes128GcmIv12Tag16),
  // [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16]: Object.freeze(webCryptoAlgAes256GcmIv12Tag16),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(webCryptoAlgAes128GcmIv12Tag16HkdfSha256),
  // [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(webCryptoAlgAes256GcmIv12Tag16HkdfSha256),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256]: Object.freeze(webCryptoAlgAes128GcmIv12Tag16HkdfSha256EcdsaP256),
  // [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(webCryptoAlgAes192GcmIv12Tag16HkdfSha384EcdsaP384),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(webCryptoAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384)
})

export class WebCryptoAlgorithmSuite extends AlgorithmSuite implements IWebCryptoAlgorithmSuite {
  encryption!: WebCryptoEncryption
  kdfHash?: WebCryptoHash
  signatureCurve?: WebCryptoECDHCurve
  signatureHash?: WebCryptoHash
  type: AlgorithmSuiteTypeWebCrypto = 'webCrypto'
  constructor (id: AlgorithmSuiteIdentifier) {
    super(webCryptoAlgorithms[id])
    /* Precondition: Browsers do not support 192 bit keys so the AlgorithmSuiteIdentifier is removed.
     * This is primarily an error in decrypt but this make it clear.
     * The error can manifest deep in the decrypt loop making it hard to debug.
     */
    needs(supportedWebCryptoAlgorithms.hasOwnProperty(id), '192-bit AES keys are not supported')
    Object.setPrototypeOf(this, WebCryptoAlgorithmSuite.prototype)
    Object.freeze(this)
  }
}

Object.freeze(WebCryptoAlgorithmSuite.prototype)
Object.freeze(WebCryptoAlgorithmSuite)
