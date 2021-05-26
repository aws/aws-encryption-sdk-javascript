// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringBrowser,
  KMS,
  getClient,
  buildClient,
  CommitmentPolicy,
} from '@aws-crypto/client-browser'

/* A KMS CMK is required to generate the data key.
 * You need kms:GenerateDataKey permission on the CMK in generatorKeyId.
 */
const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

/* An alternate KMS key that can decrypt.
 * Access to kms:Encrypt is required.
 */
const alternateKeyId =
  'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'

const commitmentPolicy = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT

/* replicate(length, val) is an array containing `length` many copies of `val`.
 */
function replicate<T>(length: number, val: T): T[] {
  return Array.from({ length }, () => val)
}

declare const credentials: {
  accessKeyId: string
  secretAccessKey: string
  sessionToken: string
}

export async function kmsEncryptWithMaxEncryptedDataKeysTest(numKeys: number) {
  /* Encrypting client allows 3 encrypted data keys.
   * Decrypting client has no limit.
   */
  const { encrypt } = buildClient({ commitmentPolicy, maxEncryptedDataKeys: 3 })
  const { decrypt } = buildClient({
    commitmentPolicy,
    maxEncryptedDataKeys: false,
  })

  /* `keyring` has a total of `numKeys`-many keys. */
  const keyring = new KmsKeyringBrowser({
    clientProvider: getClient(KMS, { credentials }),
    generatorKeyId,
    keyIds: replicate(numKeys - 1, alternateKeyId),
  })

  /* Encrypt and decrypt. */
  const cleartext = new Uint8Array([1, 2, 3, 4, 5])
  const { result } = await encrypt(keyring, cleartext)
  const { plaintext } = await decrypt(keyring, result)

  /* Return the values for testing. */
  return { plaintext, result, cleartext }
}

/**
 * Try decrypting a ciphertext with `numKeys` many keys, where the decrypting
 * client has `maxEncryptedDataKeys` set to 3.
 */
export async function kmsDecryptWithMaxEncryptedDataKeysTest(numKeys: number) {
  const { encrypt } = buildClient({
    commitmentPolicy,
    maxEncryptedDataKeys: false,
  })
  const { decrypt } = buildClient({ commitmentPolicy, maxEncryptedDataKeys: 3 })

  /* `keyring` has a total of `numKeys`-many keys. */
  const keyring = new KmsKeyringBrowser({
    clientProvider: getClient(KMS, { credentials }),
    generatorKeyId,
    keyIds: replicate(numKeys - 1, alternateKeyId),
  })

  /* Encrypt and decrypt. */
  const cleartext = new Uint8Array([1, 2, 3, 4, 5])
  const { result } = await encrypt(keyring, cleartext)
  const { plaintext } = await decrypt(keyring, result)

  /* Return the values for testing. */
  return { plaintext, result, cleartext }
}
