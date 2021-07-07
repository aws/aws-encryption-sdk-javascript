// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// noinspection ES6UnusedImports
/* eslint-disable @typescript-eslint/no-unused-vars */ //For mocks
/* eslint-env mocha */

import { expect } from 'chai'
import { fromBase64 } from '@aws-sdk/util-base64-browser'
import { KeyInfoTuple, TestVectorResult } from '@aws-crypto/integration-vectors'
import {
  KeyringWebCrypto,
  MultiKeyringWebCrypto,
  WebCryptoMaterialsManager,
  DecryptResult,
  MessageHeader,
} from '@aws-crypto/client-browser'
import {
  testNegativeDecryptFixture,
  testPositiveDecryptFixture,
  notSupportedDecryptMessages,
  expectedNotActualPlaintextMessage,
  evaluateTestResultIgnoreUnsupported,
} from '../src/testDecryptFixture'
import {
  MockedCmm,
  validPlaintext,
  validPositiveTest,
  validNegativeTest,
  validErrorDescription,
  failMeText,
  MockedKeyInfoTuple,
} from './unitTestConstants'

// noinspection JSUnusedLocalSymbols
async function mockDecrypt(
  //@ts-ignore
  cmm: KeyringWebCrypto | WebCryptoMaterialsManager,
  //@ts-ignore
  ciphertext: Uint8Array
): Promise<DecryptResult> {
  const err = (<MockedCmm>cmm).err
  if (!err)
    return {
      plaintext: fromBase64(validPlaintext),
      messageHeader: <MessageHeader>{},
    }
  throw new Error(err)
}

async function mockGetCmm(
  keyInfos: KeyInfoTuple[]
): Promise<MultiKeyringWebCrypto> {
  return <MultiKeyringWebCrypto>(
    (<unknown>(<MockedKeyInfoTuple>(<unknown>keyInfos)).mockedCmm)
  )
}

describe('testDecryptFixtures', () => {
  describe('The function testPositiveDecryptFixture', () => {
    it(
      'returns a testResultVector with result TRUE if ' +
        'the expected plaintext is equal to the actual plaintext ',
      async () => {
        const actualResults: TestVectorResult =
          await testPositiveDecryptFixture(
            validPositiveTest.name,
            fromBase64(validPlaintext),
            fromBase64(validPositiveTest.cipherText),
            <KeyInfoTuple[]>(<unknown>(<MockedKeyInfoTuple>{
              mockedCmm: <MockedCmm>{},
            })),
            mockDecrypt,
            mockGetCmm
          )
        expect(actualResults.result).to.be.true
        expect(actualResults.name).to.be.equal(validPositiveTest.name)
        expect(actualResults.err).to.be.undefined
        expect(actualResults.description).to.be.undefined
      }
    )
    it(
      'returns a testResultVector with FALSE and correct Error message' +
        'if the decryption scheme is unsupported',
      async () => {
        const actualResults: TestVectorResult =
          await testPositiveDecryptFixture(
            validPositiveTest.name,
            fromBase64(validPlaintext),
            fromBase64(validPositiveTest.cipherText),
            <KeyInfoTuple[]>(<unknown>(<MockedKeyInfoTuple>{
              mockedCmm: <MockedCmm>{ err: notSupportedDecryptMessages[0] },
            })),
            mockDecrypt,
            mockGetCmm
          )
        expect(actualResults.result).to.be.false
        expect(actualResults.err).to.have.property(
          'message',
          notSupportedDecryptMessages[0]
        )
      }
    )
    it(
      'returns a testResultVector with FALSE and Err' +
        'if the actualPlaintext did not meet the expected plaintext',
      async () => {
        const actualResults: TestVectorResult =
          await testPositiveDecryptFixture(
            validPositiveTest.name,
            fromBase64(failMeText),
            fromBase64(validPositiveTest.cipherText),
            <KeyInfoTuple[]>(<unknown>(<MockedKeyInfoTuple>{
              mockedCmm: <MockedCmm>{},
            })),
            mockDecrypt,
            mockGetCmm
          )
        expect(actualResults.result).to.be.false
        expect(actualResults.err).to.have.property('message')
        if (actualResults.err && actualResults.err.message)
          expect(actualResults.err.message).to.include(
            expectedNotActualPlaintextMessage
          )
      }
    )
  })

  describe('The function testNegativeDecryptFixture', () => {
    it(
      'returns TRUE if ' +
        'an error is thrown and the decryption scheme is supported',
      async () => {
        const actualResults: TestVectorResult =
          await testNegativeDecryptFixture(
            validNegativeTest.name,
            validErrorDescription,
            fromBase64(validNegativeTest.cipherText),
            <KeyInfoTuple[]>(<unknown>(<MockedKeyInfoTuple>{
              mockedCmm: <MockedCmm>{ err: validErrorDescription },
            })),
            mockDecrypt,
            mockGetCmm
          )
        expect(actualResults.result).to.be.true
        expect(actualResults.name).to.be.equal(validNegativeTest.name)
        expect(actualResults.err).to.be.undefined
        expect(actualResults.description).to.be.undefined
      }
    )
    it(
      'returns FALSE and correct Error message if' +
        'the decryption scheme is unsupported',
      async () => {
        const actualResults: TestVectorResult =
          await testNegativeDecryptFixture(
            validNegativeTest.name,
            validErrorDescription,
            fromBase64(validNegativeTest.cipherText),
            <KeyInfoTuple[]>(<unknown>(<MockedKeyInfoTuple>{
              mockedCmm: <MockedCmm>{ err: notSupportedDecryptMessages[1] },
            })),
            mockDecrypt,
            mockGetCmm
          )
        expect(actualResults.result).to.be.false
        expect(actualResults.err).to.have.property(
          'message',
          notSupportedDecryptMessages[1]
        )
      }
    )
    it(
      'returns FALSE and correct Error message if' +
        ' the decrypt method does not throw an error',
      async () => {
        const actualResults: TestVectorResult =
          await testNegativeDecryptFixture(
            validNegativeTest.name,
            validErrorDescription,
            fromBase64(validNegativeTest.cipherText),
            <KeyInfoTuple[]>(<unknown>(<MockedKeyInfoTuple>{
              mockedCmm: <MockedCmm>{},
            })),
            mockDecrypt,
            mockGetCmm
          )
        expect(actualResults.result).to.be.false
        expect(actualResults.err).to.have.property('message')
        if (actualResults.err && actualResults.err.message)
          expect(actualResults.err.message).to.include(
            `Expected to fail with ${validErrorDescription}`
          )
      }
    )
  })

  function mockExpect(x: any): any {
    return {
      toEqual: (y: boolean, err?: Error) => {
        if (<boolean>x == y) return
        if (err) throw err
        throw new Error('Actual did not equal expected')
      },
    }
  }

  describe('The mockExpect ', () => {
    let throughError = false
    it('throws an error when comparing true & false', function () {
      throughError = false
      try {
        mockExpect(false).toEqual(true, new Error('fudge'))
      } catch (err) {
        throughError = true
      }
      expect(throughError).to.be.true
    })
    it('does nothing when comparing true & true or false & false', function () {
      throughError = false
      try {
        mockExpect(true).toEqual(true, new Error('fudge'))
        mockExpect(false).toEqual(false, new Error('fudge'))
      } catch (err) {
        throughError = true
      }
      expect(throughError).to.be.false
    })
  })

  describe('The method evaluateTestResultIgnoreUnsupported ', () => {
    let throughError = false
    const ignoreTestResult: TestVectorResult = {
      name: 'ignore this test',
      result: false,
      err: new Error(notSupportedDecryptMessages[0]),
    }
    const passTestResult: TestVectorResult = {
      name: 'pass test result',
      result: true,
    }
    const failTestResult: TestVectorResult = {
      name: 'failed test result',
      result: false,
      err: new Error('fudge'),
    }
    it('ignores unsupported errors', () => {
      throughError = false
      try {
        evaluateTestResultIgnoreUnsupported(ignoreTestResult, mockExpect)
      } catch (err) {
        throughError = true
      }
      expect(throughError).to.be.false
    })
    it('passes passing test results', () => {
      throughError = false
      try {
        evaluateTestResultIgnoreUnsupported(passTestResult, mockExpect)
      } catch (err) {
        throughError = true
      }
      expect(throughError).to.be.false
    })
    it('fails failing test results', () => {
      throughError = false
      try {
        evaluateTestResultIgnoreUnsupported(failTestResult, mockExpect)
      } catch (err) {
        throughError = true
      }
      expect(throughError).to.be.true
    })
  })
})
