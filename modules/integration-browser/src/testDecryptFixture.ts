// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KeyringWebCrypto,
  MultiKeyringWebCrypto,
  WebCryptoMaterialsManager,
  DecryptResult,
} from '@aws-crypto/client-browser'
import {
  DecryptionFixture,
  KeyInfoTuple,
  TestVectorResult,
} from '@aws-crypto/integration-vectors'
import { decryptMaterialsManagerWebCrypto } from './decrypt_materials_manager_web_crypto'
import { fromBase64 } from '@aws-sdk/util-base64-browser'

export const expectedNotActualPlaintextMessage = `Decrypted plaintext did not match expected plaintext`

export const notSupportedDecryptMessages = [
  '192-bit AES keys are not supported',
  'Unsupported right now',
]

// These vectors successfully decrypt when they shouldn't due to
// overly permissive DER decoding in asn1.js.
// See https://github.com/indutny/asn1.js/pull/128
export const bitFlippedDerTagsVectors = [
  'c415e987-48ff-4da3-a70a-2fe67c25b700', // Bit 2944 flipped
  '470419df-6280-4813-8f53-ab9f2c979dee', // Bit 2945 flipped
  '3bf06756-45b2-4fa7-85d2-e636e221da07', // Bit 2946 flipped
  'd4e4cf08-1a0c-48ca-83ae-7f63bd8e8ba4', // Bit 2960 flipped
  '114d533b-7ead-4601-b87b-42d25c28c2ef', // Bit 2961 flipped
  '8f38fb88-539a-4a53-b9d2-031fc6bfadf7', // Bit 2962 flipped
  '32640303-2f79-44a2-83cd-476e22360491', // Bit 3368 flipped
  '4e6151b0-8799-4c69-9b1a-6223cfce795d', // Bit 3369 flipped
  'c33a0daa-806e-428c-8558-def65f41817b', // Bit 3370 flipped
]

// The signatures on these messages fail to verify due to
// a known but yet to be fully diagnosed browser-specific issue.
export const unverifiableSignatureVectors = [
  '55c1a27a-70ec-4d3a-8dda-d718eef0a532',
  'c0a92e53-f75b-4168-81ae-3cdd69f8dd0c',
]

/*The contract for the two test*DecryptFixture methods:
 * If the decryption is NOT supported,
 *  FAILED with err.message in notSupportedDecryptMessages
 * If the actual plaintext does not match the expected plaintext,
 *  it FAILED with err.message as expectedNotActualPlaintextMessage
 * If it is a negative test, and it throws
 *  an error outside of notSupportedDecryptMessages, it PASSED.
 * If it is a negative test, and it does not throw an error, it FAILED
 */

export async function testPositiveDecryptFixture(
  name: string,
  expectedPlainText: Uint8Array,
  cipher: Uint8Array,
  keyInfo: KeyInfoTuple[],
  _decrypt: (
    cmm: KeyringWebCrypto | WebCryptoMaterialsManager,
    ciphertext: Uint8Array
  ) => Promise<DecryptResult>,
  _getCmm: (keyInfos: KeyInfoTuple[]) => Promise<MultiKeyringWebCrypto>
): Promise<TestVectorResult> {
  let decryptResult: DecryptResult
  try {
    const cmm = await _getCmm(keyInfo)
    decryptResult = await _decrypt(cmm, cipher)
    if (
      expectedPlainText
        .toString()
        .localeCompare(decryptResult.plaintext.toString()) == 0
    ) {
      return { result: true, name }
    }
    // noinspection ExceptionCaughtLocallyJS
    throw new Error(
      expectedNotActualPlaintextMessage +
        `\n expected plaintext: ${expectedPlainText}` +
        `\n actual plaintext: ${decryptResult.plaintext}`
    )
  } catch (err) {
    return { result: false, name, err }
  }
}

export async function testNegativeDecryptFixture(
  name: string,
  errorDescription: string,
  cipher: Uint8Array,
  keyInfos: KeyInfoTuple[],
  _decrypt: (
    cmm: KeyringWebCrypto | WebCryptoMaterialsManager,
    ciphertext: Uint8Array
  ) => Promise<DecryptResult>,
  _getCmm: (keyInfos: KeyInfoTuple[]) => Promise<MultiKeyringWebCrypto>
): Promise<TestVectorResult> {
  let decryptResult: DecryptResult
  try {
    const cmm = await _getCmm(keyInfos)
    decryptResult = await _decrypt(cmm, cipher)
  } catch (err) {
    if (notSupportedDecryptMessages.includes(err.message))
      return { result: false, name, err: err }
    return { result: true, name }
  }
  return {
    result: false,
    name,
    err: new Error(
      `Expected to fail with ${errorDescription}, but succeeded with decrypt result:` +
        `\n header: ${decryptResult.messageHeader}` +
        `\n plaintext: ${decryptResult.plaintext}`
    ),
  }
}

export async function decryptionIntegrationBrowserTest(
  { cipherText, description, keysInfo, name, result }: DecryptionFixture,
  decrypt: (
    cmm: KeyringWebCrypto | WebCryptoMaterialsManager,
    ciphertext: Uint8Array
  ) => Promise<DecryptResult>,
  _expect: (x: any) => any
): Promise<void> {
  let testResult: TestVectorResult = {
    name: name,
    result: false,
    err: new Error(`Unsupported 'result' in decryption test fixture ${result}`),
  }
  if ('plainText' in result) {
    console.log(`start positive test: ${name}; ${description}`)
    testResult = await testPositiveDecryptFixture(
      name,
      fromBase64(result.plainText),
      fromBase64(cipherText),
      keysInfo,
      decrypt,
      decryptMaterialsManagerWebCrypto
    )
  }
  if ('errorDescription' in result) {
    const errorDescription = result.errorDescription
    console.log(
      `start negative test: ${name}; ${description}; expected error ${errorDescription}`
    )
    testResult = await testNegativeDecryptFixture(
      name,
      errorDescription,
      fromBase64(cipherText),
      keysInfo,
      decrypt,
      decryptMaterialsManagerWebCrypto
    )
  }
  return evaluateTestResultIgnoreUnsupported(testResult, _expect)
}

export function evaluateTestResultIgnoreUnsupported(
  { err, name, result }: TestVectorResult,
  _expect: (x: any) => any
): void {
  if (
    bitFlippedDerTagsVectors.includes(name) ||
    unverifiableSignatureVectors.includes(name)
  ) {
    return _expect(result).toEqual(false)
  }
  if (err && err['message']) {
    const message = err.message
    if (notSupportedDecryptMessages.includes(message)) {
      // We expect unsupported decryption schemes to fail
      return _expect(result).toEqual(false)
    }
  } // Otherwise, we expect tests to pass
  if (!result) {
    // We have had trouble with karma/jasmine reporting the err passed to
    // its `toEqual` matcher so we log/fail the test explicitly
    console.error(`${name} FAILED`) //
    throw err
  }
  return _expect(result).toEqual(true, err)
}
