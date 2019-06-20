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

/* This is a simple example of using a raw RSA Keyring
 * to encrypt and decrypt using the AWS Encryption SDK for Javascript in a browser.
 */

import {
  RsaImportableKey, // eslint-disable-line no-unused-vars
  RawRsaKeyringWebCrypto,
  encrypt,
  decrypt
} from '@aws-crypto/client-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'

;(async function testRSA () {
  /* JWK for the RSA Keys to use.
   * These keys are *Public*!
   * *DO NOT USE*
   */
  const privateRsaJwkKey: RsaImportableKey = { 'alg': 'RSA-OAEP-256', 'd': 'XcAlS3OYtZ5F3BFGRQH5B8soiqstUk9JkH6_sUhBUfM7yjFpn3MQACtGgOKsFIO01KWCVl7Cn6E3c-MuuT3QqNQrUx8n-WrJU8qNpDOGJ5CVpG9-xTSQVNzRV92gj8g7-BIgehtzMmirXXNsb1XeTg9zsm3iptt9VyhplGqcgOdmm72sT1Z8ZmkagaElHSg0dR1ZNGgzSfTtRg_J1tTh7cmFb1LVz069o6cRaa5ueOPNKxmEslBdVWsDo9naxd_keLiqOOMIQp-KlLuQ-Zhn5fZyqxkRPGjTKZZHitgurzfWG4ERjjrYCbZsOjEt9Tj8FXXUB8bd3qRPy5UkN-XLEQ', 'dp': 'V8QYdWm4OqWpfF_NPdCGr5eqztfHiQQn1NLmkvNO8c9dc2yNizZ4GxtNNEARYjgnLK0ROCoiK5yamtVDyjZ_zzZUvE0CG8iNRg1qvaOM8n_7B2YgmUs9rJ-QKK3HVEsi_M0x-hHeRl3ocAkNfby3__yt6s43FvyrccQh89WcAr0', 'dq': 'NT5lrYlvkOwXIHl8P9AQm1nNL0RkHSrWahYlagRkyU3ELySlWr2laDxXzPnngpuBvyA98iq6Z2JTn8ArtXXvTqQk6BF6np6qqg1QNQxsQeU4Aj3xOMV9EGh57Zpa8Rs0jVydxBdlRW03Fr0UChHKxmT2kS0622gdlGQAs3YxMck', 'e': 'AQAB', 'ext': true, 'key_ops': ['unwrapKey'], 'kty': 'RSA', 'n': '6k_jrxg7mpz7CzgAr6eRqJr1VlvjJ9uQY71hadkDZkLLZHiMl7hz73lqq3w2MfHCa3Pf3BVo5TCXGYuxKOlPb7bH0WWpMeAzOKR_X27UqfA8MBVGb4YO5HXqw0jup8-I-Zi3CQAmP87uE6GDuh7xzeAcwpGD5xE0N74-uWq3YS92PFHCavtryx-ad9VGTgfAbkV3k1-RSxIiZjzbAt3exBAn5EjMfF6FMI70_HYqO-5xGv_aAPSa1OMc_buK5QACN7gmFwqHBzw98v93iyGUc4_XJNL-jPzKNP4AT1zMc6p6RxF3SYytNq7iXIjUmm-oY8fvCSmT1F13XKdzv7DLOw', 'p': '9dGuBwEDeOHFwJ_AQXHBWu53bv_L1_9lh2X-NEBO1B7YMhYWu2nMqXEvLpwvPqyBXwWnuPdfGqu6BHv22RDAF7Lu_oUshq-9dzSwFxaC5PQ2NwtHnz0-zwhEzCE3Qw9t63_OXX87gjp5vy6c5bvb3B9EbZU33Xf9nqVEJhzFreU', 'q': '9AQ0oYhctBbFuIu4jt1HBmqQGGAECbhQAMw324MX8pVUg6GOtF0X822iEsq7aIfY8u5nTWu1kKl6s84US1yII0sJmW2Jj722r5VYDIrxk5x_mLQ6jXmfuH2kl-Lvzo6aHIVkDLIK-IaPt5teSwG71QfAPDgR6drIAuSFnJZ2Ap8', 'qi': 'mfoT9tmXPhLBanX5Mg76pO21NAXR1aAQ76tS1_hJZYxP8iZtmlEdvvAMIdSibvIt7Gfi60rBPnxqmmKuitJfzIVCd4sVLjIVEjT_njjLAzU-NTQdGugPCWWo8jB8NyeFy6nrZa_Hy52ijBn-Xt5G8pzvz5lF5gRfCe09y14oNeQ' }
  const publicRsaJwkKey: RsaImportableKey = { 'alg': 'RSA-OAEP-256', 'e': 'AQAB', 'ext': true, 'key_ops': ['wrapKey'], 'kty': 'RSA', 'n': '6k_jrxg7mpz7CzgAr6eRqJr1VlvjJ9uQY71hadkDZkLLZHiMl7hz73lqq3w2MfHCa3Pf3BVo5TCXGYuxKOlPb7bH0WWpMeAzOKR_X27UqfA8MBVGb4YO5HXqw0jup8-I-Zi3CQAmP87uE6GDuh7xzeAcwpGD5xE0N74-uWq3YS92PFHCavtryx-ad9VGTgfAbkV3k1-RSxIiZjzbAt3exBAn5EjMfF6FMI70_HYqO-5xGv_aAPSa1OMc_buK5QACN7gmFwqHBzw98v93iyGUc4_XJNL-jPzKNP4AT1zMc6p6RxF3SYytNq7iXIjUmm-oY8fvCSmT1F13XKdzv7DLOw' }

  /* The RSA private key needs to be imported to a CryptoKey. */
  const privateKey = await RawRsaKeyringWebCrypto.importPrivateKey(privateRsaJwkKey)
  /* The RSA public key needs to be imported to a CryptoKey. */
  const publicKey = await RawRsaKeyringWebCrypto.importPublicKey(publicRsaJwkKey)

  /* Raw providers need to have a name and a namespace.
   * These values *must* match *case sensitive exactly* on the decrypt side.
   * In this case I chose the Thumbprint of the RSA key as the keyName.
   */
  const keyName = '8CED2FD20FC88A9C06EFDB073707EB1EF1655780'
  const keyNamespace = 'Example RSA Provider'

  /* The Raw RSA Keyring must be configured with the desired CryptoKeys. */
  const keyring = new RawRsaKeyringWebCrypto({ keyName, keyNamespace, publicKey, privateKey })

  /* Encryption Context is a *very* powerful tool for controlling and managing access.
   * It is ***not*** secret!
   * Remember encrypted data is opaque, encryption context will help your run time checking.
   * Just because you have decrypted a JSON file, and it successfully parsed,
   * does not mean it is the intended JSON file.
   */
  const context = {
    stage: 'demo',
    purpose: 'simple demonstration app',
    origin: 'us-west-2'
  }

  /* I need something to encrypt. */
  const plainText = new Uint8Array([1, 2, 3, 4, 5])

  /* Encrypt the data. */
  const { cipherMessage } = await encrypt(keyring, plainText, { encryptionContext: context })

  /* Log the plain text,
   * only for testing and to show that it works.
   */
  console.log('plainText:', plainText)
  document.write('</br>plainText:' + plainText + '</br>')

  /* In case you want to check compatibility, I log the cipher text. */
  const cipherMessageBase64 = toBase64(cipherMessage)
  console.log(cipherMessageBase64)
  document.write(cipherMessageBase64)

  const { clearMessage, messageHeader } = await decrypt(keyring, cipherMessage)

  /* Grab the encryption context so I can verify it. */
  const { encryptionContext } = messageHeader

  /* Verify the encryption context.
   * Depending on the Algorithm Suite, the `encryptionContext` _may_ contain additional values.
   * In Signing Algorithm Suites the public verification key is serialized into the `encryptionContext`.
   * So it is best to make sure that all the values that you expect exist as opposed to the reverse.
   */
  Object
    .entries(context)
    .forEach(([key, value]) => {
      if (encryptionContext[key] !== value) throw new Error('Encryption Context does not match expected values')
    })

  /* Log the clear message,
   * only for testing and to show that it works.
   */
  document.write('</br>clearMessage:' + clearMessage)
  console.log(clearMessage)
})()
