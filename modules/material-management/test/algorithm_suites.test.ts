// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  AlgorithmSuite,
  AlgorithmSuiteIdentifier,
  CommitmentPolicy,
  CommitmentPolicySuites,
  CommittingAlgorithmSuiteIdentifier,
  NonSigningAlgorithmSuiteIdentifier,
  SignaturePolicy,
  SignaturePolicySuites,
} from '../src/algorithm_suites'

describe('AlgorithmSuiteIdentifier', () => {
  it('should be frozen', () => {
    expect(Object.isFrozen(AlgorithmSuiteIdentifier)).to.eql(true)
  })
})

describe('AlgorithmSuite', () => {
  it('should not allow an instance', () => {
    // @ts-expect-error Trying to test something that Typescript should deny...
    expect(() => new AlgorithmSuite()).to.throw(
      'new AlgorithmSuite is not allowed'
    )
  })

  it('prototype should be immutable', () => {
    expect(Object.isFrozen(AlgorithmSuite.prototype))
  })

  it('Precondition: A algorithm suite specification must be passed.', () => {
    class Test extends AlgorithmSuite {}

    expect(() => new Test(undefined as any)).to.throw(
      'Algorithm specification not set.'
    )
  })

  it('Precondition: The Algorithm Suite Identifier must exist.', () => {
    class Test extends AlgorithmSuite {}

    expect(() => new Test({ id: 'does not exist' } as any)).to.throw(
      'No suite by that identifier exists.'
    )
  })
})

describe('CommitmentPolicySuites', () => {
  class Test extends AlgorithmSuite {}
  it('isEncryptEnabled allows enabled suite', () => {
    const test = new Test({
      id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
    } as any)

    expect(() =>
      CommitmentPolicySuites.isEncryptEnabled(
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        test
      )
    ).to.not.throw()
  })

  it('isDecryptEnabled allows enabled suite', () => {
    const test = new Test({
      id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
    } as any)

    expect(() =>
      CommitmentPolicySuites.isDecryptEnabled(
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        test,
        'asdf'
      )
    ).to.not.throw()
  })

  it('Precondition: Only handle EncryptionMaterial for algorithm suites supported in commitmentPolicy.', () => {
    const testCommitmentPolicySuites = {
      isEncryptEnabled: CommitmentPolicySuites.isEncryptEnabled,
      fake_policy: {
        encryptEnabledSuites: CommittingAlgorithmSuiteIdentifier,
      },
    }

    const test = new Test({
      id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
    } as any)
    expect(() =>
      testCommitmentPolicySuites.isEncryptEnabled('fake_policy' as any, test)
    ).to.throw('Configuration conflict. Cannot encrypt due to CommitmentPolicy')
  })

  it('Precondition: Only handle DecryptionMaterial for algorithm suites supported in commitmentPolicy.', () => {
    const testCommitmentPolicySuites = {
      isDecryptEnabled: CommitmentPolicySuites.isDecryptEnabled,
      fake_policy: {
        decryptEnabledSuites: CommittingAlgorithmSuiteIdentifier,
      },
    }

    const test = new Test({
      id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
    } as any)
    expect(() =>
      testCommitmentPolicySuites.isDecryptEnabled(
        'fake_policy' as any,
        test,
        'messageID'
      )
    ).to.throw('Configuration conflict. Cannot process message with ID')
  })
})

describe('SignaturePolicySuites', () => {
  class Test extends AlgorithmSuite {}
  const messageId = 'messageId'
  describe('handles signing suites correctly', () => {
    const test = new Test({
      id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
    } as any)
    it('isDecryptEnabled allows Signing suites for decrypting with policy ALLOW_DECRYPT', () => {
      expect(() =>
        SignaturePolicySuites.isDecryptEnabled(
          SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
          test,
          messageId
        )
      ).to.not.throw()
    })

    it('isDecryptEnabled forbids Signing suites for decrypting with policy FORBID_DECRYPT', () => {
      expect(() =>
        SignaturePolicySuites.isDecryptEnabled(
          SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT,
          test,
          messageId
        )
      ).to.throw('Configuration conflict. Cannot process message with ID')
    })
  })

  describe('handles non-signing suites correctly', () => {
    const test = new Test({
      id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
    } as any)
    //TODO: Get Robin or Alex Chew to validate this correct... it seems off to me...
    it('isDecryptEnabled allows non-signing suite for decrypting with policy ALLOW_DECRYPT', () => {
      expect(() =>
        SignaturePolicySuites.isDecryptEnabled(
          SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
          test,
          messageId
        )
      ).to.not.throw()
    })

    it('isDecryptEnabled allows non-signing suites for decrypting with policy FORBID_DECRYPT', () => {
      expect(() =>
        SignaturePolicySuites.isDecryptEnabled(
          SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT,
          test,
          messageId
        )
      ).to.not.throw()
    })
  })

  it('Precondition: Only handle DecryptionMaterial for algorithm suites supported in signaturePolicy.', () => {
    const testCommitmentPolicySuites = {
      isDecryptEnabled: SignaturePolicySuites.isDecryptEnabled,
      fake_policy: {
        decryptEnabledSuites: NonSigningAlgorithmSuiteIdentifier,
      },
    }

    const test = new Test({
      id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
    } as any)
    expect(() =>
      testCommitmentPolicySuites.isDecryptEnabled(
        'fake_policy' as any,
        test,
        messageId
      )
    ).to.throw('Configuration conflict. Cannot process message with ID')
  })
})
