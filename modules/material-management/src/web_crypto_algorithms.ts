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

/*
 * This file contains information about particular algorithm suites used
 * within the encryption SDK.  In most cases, end-users don't need to
 * manipulate this structure, but it can occasionally be needed for more
 * advanced use cases, such as writing keyrings.
 * 
 * Simply encrypting things with a given algorithm is not adequate protection.
 * Clever people can defeat simple crypto schemes.  The integrity of the
 * payload must also be insured.  So the encryption SDK uses a defence in
 * depth strategy to combine various cryptographic primitives
 * to insure privacy.  Here we have the additional problem of
 * WebCrypto vs OpenSSL (node) and how they name things.
 * 
 * These are the WebCrypto specific values the AWS Encryption SDK for JavaScript
 * Algorithm Suites.
 */


import {AlgorithmSuite, AlgorithmSuiteIdentifier, IWebCryptoAlgorithmSuite}  from './algorithm_suites'
import {WebCryptoEncryption, WebCryptoHash, WebCryptoECDHCurve, AlgorithmSuiteTypeWebCrypto} from './algorithm_suites'

const web_crypto_alg_aes128_gcm_iv12_tag16: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
  encryption: 'AES-GCM',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
const web_crypto_alg_aes192_gcm_iv12_tag16: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16,
  encryption: 'AES-GCM',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
const web_crypto_alg_aes256_gcm_iv12_tag16: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  cacheSafe: false
}
const web_crypto_alg_aes128_gcm_iv12_tag16_hkdf_sha256: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'AES-GCM',
  keyLength: 128,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true
}
const web_crypto_alg_aes192_gcm_iv12_tag16_hkdf_sha256: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'AES-GCM',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true
}
const web_crypto_alg_aes256_gcm_iv12_tag16_hkdf_sha256: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-256',
  cacheSafe: true
}
const web_crypto_alg_aes128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256: IWebCryptoAlgorithmSuite = {
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
const web_crypto_alg_aes192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  encryption: 'AES-GCM',
  keyLength: 192,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-384',
  cacheSafe: true,
  signatureCurve: 'P-384',
  signatureHash: 'SHA-384',
}
const web_crypto_alg_aes256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384: IWebCryptoAlgorithmSuite = {
  id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  encryption: 'AES-GCM',
  keyLength: 256,
  ivLength: 12,
  tagLength: 128,
  kdf: 'HKDF',
  kdfHash: 'SHA-384',
  cacheSafe: true,
  signatureCurve: 'P-384',
  signatureHash: 'SHA-384',
}

type WebCryptoAlgorithms = Readonly<{[id in AlgorithmSuiteIdentifier]: IWebCryptoAlgorithmSuite}>
const webCryptoAlgorithms: WebCryptoAlgorithms = Object.freeze({
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16]: Object.freeze(web_crypto_alg_aes128_gcm_iv12_tag16),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16]: Object.freeze(web_crypto_alg_aes192_gcm_iv12_tag16),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16]: Object.freeze(web_crypto_alg_aes256_gcm_iv12_tag16),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(web_crypto_alg_aes128_gcm_iv12_tag16_hkdf_sha256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(web_crypto_alg_aes192_gcm_iv12_tag16_hkdf_sha256),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256]: Object.freeze(web_crypto_alg_aes256_gcm_iv12_tag16_hkdf_sha256),
  [AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256]: Object.freeze(web_crypto_alg_aes128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256),
  [AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(web_crypto_alg_aes192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384),
  [AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384]: Object.freeze(web_crypto_alg_aes256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384),
})

export class WebCryptoAlgorithmSuite extends AlgorithmSuite implements IWebCryptoAlgorithmSuite {
  encryption!: WebCryptoEncryption
  kdfHash?: WebCryptoHash
  signatureCurve?: WebCryptoECDHCurve
  signatureHash?: WebCryptoHash
  type: AlgorithmSuiteTypeWebCrypto = 'webCrypto'
  constructor(id: AlgorithmSuiteIdentifier) {
    super(webCryptoAlgorithms[id])
    Object.freeze(this)
  }
}

Object.freeze(WebCryptoAlgorithmSuite.prototype)
Object.freeze(WebCryptoAlgorithmSuite)
