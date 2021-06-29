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
  '82f59ef1-7002-486d-9679-f4b358e6f05e', // Bit 2944 flipped
  '516abc51-d740-4715-8888-73ebf1c3b674', // Bit 2945 flipped
  '6911b1b6-238c-4c82-a27c-31a21a770380', // Bit 2946 flipped
  '9e5dd64e-fa70-42cf-9f32-7168710ca193', // Bit 2960 flipped
  '233e79f7-aab8-4381-9fdc-2b2b4d0efd91', // Bit 2961 flipped
  '9905767c-a214-4483-8e69-425a8b1ec833', // Bit 2962 flipped
  'b40cecee-bff8-45c0-9679-a7533ce8ad75', // Bit 3368 flipped
  '1f665dd8-08f3-43b0-96ab-deca39634bea', // Bit 3369 flipped
  'f673bdf3-40a8-4551-bc7f-866b289e4d03', // Bit 3370 flipped
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
  if (bitFlippedDerTagsVectors.includes(name)) {
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
