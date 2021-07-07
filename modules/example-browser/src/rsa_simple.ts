// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is a simple example of using a raw RSA keyring
 * to encrypt and decrypt using the AWS Encryption SDK for Javascript
 * in a browser.
 */

import {
  RsaImportableKey,
  RawRsaKeyringWebCrypto,
  buildClient,
  CommitmentPolicy,
} from '@aws-crypto/client-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'

/* This builds the client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy,
 * which enforces that this client only encrypts using committing algorithm suites
 * and enforces that this client
 * will only decrypt encrypted messages
 * that were created with a committing algorithm suite.
 * This is the default commitment policy
 * if you build the client with `buildClient()`.
 */
const { encrypt, decrypt } = buildClient(
  CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

/* This is done to facilitate testing. */
export async function testRSA() {
  /* JWK for the RSA Keys to use.
   * These keys are *Public*!
   * *DO NOT USE*
   */
  const privateRsaJwkKey: RsaImportableKey = {
    alg: 'RSA-OAEP-256',
    d: 'XcAlS3OYtZ5F3BFGRQH5B8soiqstUk9JkH6_sUhBUfM7yjFpn3MQACtGgOKsFIO01KWCVl7Cn6E3c-MuuT3QqNQrUx8n-WrJU8qNpDOGJ5CVpG9-xTSQVNzRV92gj8g7-BIgehtzMmirXXNsb1XeTg9zsm3iptt9VyhplGqcgOdmm72sT1Z8ZmkagaElHSg0dR1ZNGgzSfTtRg_J1tTh7cmFb1LVz069o6cRaa5ueOPNKxmEslBdVWsDo9naxd_keLiqOOMIQp-KlLuQ-Zhn5fZyqxkRPGjTKZZHitgurzfWG4ERjjrYCbZsOjEt9Tj8FXXUB8bd3qRPy5UkN-XLEQ',
    dp: 'V8QYdWm4OqWpfF_NPdCGr5eqztfHiQQn1NLmkvNO8c9dc2yNizZ4GxtNNEARYjgnLK0ROCoiK5yamtVDyjZ_zzZUvE0CG8iNRg1qvaOM8n_7B2YgmUs9rJ-QKK3HVEsi_M0x-hHeRl3ocAkNfby3__yt6s43FvyrccQh89WcAr0',
    dq: 'NT5lrYlvkOwXIHl8P9AQm1nNL0RkHSrWahYlagRkyU3ELySlWr2laDxXzPnngpuBvyA98iq6Z2JTn8ArtXXvTqQk6BF6np6qqg1QNQxsQeU4Aj3xOMV9EGh57Zpa8Rs0jVydxBdlRW03Fr0UChHKxmT2kS0622gdlGQAs3YxMck',
    e: 'AQAB',
    ext: true,
    key_ops: ['unwrapKey'],
    kty: 'RSA',
    n: '6k_jrxg7mpz7CzgAr6eRqJr1VlvjJ9uQY71hadkDZkLLZHiMl7hz73lqq3w2MfHCa3Pf3BVo5TCXGYuxKOlPb7bH0WWpMeAzOKR_X27UqfA8MBVGb4YO5HXqw0jup8-I-Zi3CQAmP87uE6GDuh7xzeAcwpGD5xE0N74-uWq3YS92PFHCavtryx-ad9VGTgfAbkV3k1-RSxIiZjzbAt3exBAn5EjMfF6FMI70_HYqO-5xGv_aAPSa1OMc_buK5QACN7gmFwqHBzw98v93iyGUc4_XJNL-jPzKNP4AT1zMc6p6RxF3SYytNq7iXIjUmm-oY8fvCSmT1F13XKdzv7DLOw',
    p: '9dGuBwEDeOHFwJ_AQXHBWu53bv_L1_9lh2X-NEBO1B7YMhYWu2nMqXEvLpwvPqyBXwWnuPdfGqu6BHv22RDAF7Lu_oUshq-9dzSwFxaC5PQ2NwtHnz0-zwhEzCE3Qw9t63_OXX87gjp5vy6c5bvb3B9EbZU33Xf9nqVEJhzFreU',
    q: '9AQ0oYhctBbFuIu4jt1HBmqQGGAECbhQAMw324MX8pVUg6GOtF0X822iEsq7aIfY8u5nTWu1kKl6s84US1yII0sJmW2Jj722r5VYDIrxk5x_mLQ6jXmfuH2kl-Lvzo6aHIVkDLIK-IaPt5teSwG71QfAPDgR6drIAuSFnJZ2Ap8',
    qi: 'mfoT9tmXPhLBanX5Mg76pO21NAXR1aAQ76tS1_hJZYxP8iZtmlEdvvAMIdSibvIt7Gfi60rBPnxqmmKuitJfzIVCd4sVLjIVEjT_njjLAzU-NTQdGugPCWWo8jB8NyeFy6nrZa_Hy52ijBn-Xt5G8pzvz5lF5gRfCe09y14oNeQ',
  }
  const publicRsaJwkKey: RsaImportableKey = {
    alg: 'RSA-OAEP-256',
    e: 'AQAB',
    ext: true,
    key_ops: ['wrapKey'],
    kty: 'RSA',
    n: '6k_jrxg7mpz7CzgAr6eRqJr1VlvjJ9uQY71hadkDZkLLZHiMl7hz73lqq3w2MfHCa3Pf3BVo5TCXGYuxKOlPb7bH0WWpMeAzOKR_X27UqfA8MBVGb4YO5HXqw0jup8-I-Zi3CQAmP87uE6GDuh7xzeAcwpGD5xE0N74-uWq3YS92PFHCavtryx-ad9VGTgfAbkV3k1-RSxIiZjzbAt3exBAn5EjMfF6FMI70_HYqO-5xGv_aAPSa1OMc_buK5QACN7gmFwqHBzw98v93iyGUc4_XJNL-jPzKNP4AT1zMc6p6RxF3SYytNq7iXIjUmm-oY8fvCSmT1F13XKdzv7DLOw',
  }

  /* The RSA private key needs to be imported to a CryptoKey. */
  const privateKey = await RawRsaKeyringWebCrypto.importPrivateKey(
    privateRsaJwkKey
  )
  /* The RSA public key needs to be imported to a CryptoKey. */
  const publicKey = await RawRsaKeyringWebCrypto.importPublicKey(
    publicRsaJwkKey
  )

  /* You need to specify a name
   * and a namespace for raw encryption key providers.
   * The name and namespace that you use in the decryption keyring *must* be an exact,
   * *case-sensitive* match for the name and namespace in the encryption keyring.
   */
  const keyName = '8CED2FD20FC88A9C06EFDB073707EB1EF1655780'
  const keyNamespace = 'Example RSA Provider'

  /* The Raw RSA Keyring must be configured with the desired CryptoKeys. */
  const keyring = new RawRsaKeyringWebCrypto({
    keyName,
    keyNamespace,
    publicKey,
    privateKey,
  })

  /* Encryption context is a *very* powerful tool for controlling and managing access.
   * It is ***not*** secret!
   * Encrypted data is opaque.
   * You can use an encryption context to assert things about the encrypted data.
   * Just because you can decrypt something does not mean it is what you expect.
   * For example, if you are are only expecting data from 'us-west-2',
   * the origin can identify a malicious actor.
   * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
   */
  const context = {
    stage: 'demo',
    purpose: 'simple demonstration app',
    origin: 'us-west-2',
  }

  /* Find data to encrypt. */
  const plainText = new Uint8Array([1, 2, 3, 4, 5])

  /* Encrypt the data. */
  const { result } = await encrypt(keyring, plainText, {
    encryptionContext: context,
  })

  /* Log the plain text
   * only for testing and to show that it works.
   */
  console.log('plainText:', plainText)
  document.write('</br>plainText:' + plainText + '</br>')

  /* Log the base64-encoded result
   * so that you can try decrypting it with another AWS Encryption SDK implementation.
   */
  const resultBase64 = toBase64(result)
  console.log(resultBase64)
  document.write(resultBase64)

  const { plaintext, messageHeader } = await decrypt(keyring, result)

  /* Grab the encryption context so you can verify it. */
  const { encryptionContext } = messageHeader

  /* Verify the encryption context.
   * If you use an algorithm suite with signing,
   * the Encryption SDK adds a name-value pair to the encryption context that contains the public key.
   * Because the encryption context might contain additional key-value pairs,
   * do not add a test that requires that all key-value pairs match.
   * Instead, verify that the key-value pairs you expect match.
   */
  Object.entries(context).forEach(([key, value]) => {
    if (encryptionContext[key] !== value)
      throw new Error('Encryption Context does not match expected values')
  })

  /* Log the clear message
   * only for testing and to show that it works.
   */
  document.write('</br>plaintext:' + plaintext)
  console.log(plaintext)

  /* Return the values to make testing easy. */
  return { plainText, plaintext }
}
