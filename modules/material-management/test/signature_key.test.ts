// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  SignatureKey,
  VerificationKey,
  AlgorithmSuiteIdentifier,
  NodeAlgorithmSuite,
} from '../src'

const prime256v1PublicFixture = [
  4, 54, 131, 184, 190, 94, 145, 250, 132, 150, 193, 178, 150, 190, 22, 22, 11,
  201, 60, 9, 53, 128, 68, 120, 118, 83, 106, 52, 226, 143, 155, 120, 178, 217,
  246, 201, 43, 28, 98, 154, 24, 59, 251, 229, 162, 89, 161, 79, 81, 23, 238,
  208, 108, 15, 209, 56, 91, 237, 38, 60, 72, 98, 181, 219, 196,
]

const prime256v1CompressedFixture = [
  2, 54, 131, 184, 190, 94, 145, 250, 132, 150, 193, 178, 150, 190, 22, 22, 11,
  201, 60, 9, 53, 128, 68, 120, 118, 83, 106, 52, 226, 143, 155, 120, 178,
]

describe('SignatureKey', () => {
  it('basic usage', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const sigKey = new SignatureKey(new Uint8Array(3), new Uint8Array(3), suite)
    expect(sigKey).to.haveOwnProperty('privateKey').to.be.a('string')
    expect(sigKey)
      .to.haveOwnProperty('compressPoint')
      .to.be.instanceOf(Uint8Array)
    expect(sigKey)
      .to.haveOwnProperty('signatureCurve')
      .and.to.equal(suite.signatureCurve)
  })

  it('encodeCompressPoint', () => {
    const publicKey = new Uint8Array(prime256v1PublicFixture)
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const compressPoint = SignatureKey.encodeCompressPoint(publicKey, suite)
    expect(compressPoint).to.deep.equal(
      new Uint8Array(prime256v1CompressedFixture)
    )
  })

  it('Precondition: Do not create a SignatureKey for an algorithm suite that does not have an EC named curve.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(
      () => new SignatureKey(new Uint8Array(3), new Uint8Array(3), suite)
    ).to.throw('Unsupported Algorithm')
  })

  it('Precondition: Do not return a compress point for an algorithm suite that does not have an EC named curve.', () => {
    const publicKey = new Uint8Array(prime256v1PublicFixture)
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => SignatureKey.encodeCompressPoint(publicKey, suite)).to.throw(
      'Unsupported Algorithm'
    )
  })
})

describe('VerificationKey', () => {
  it('basic usage', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const verKey = new VerificationKey(new Uint8Array(3), suite)
    expect(verKey).to.haveOwnProperty('publicKey').to.be.a('string')
    expect(verKey)
      .to.haveOwnProperty('signatureCurve')
      .and.to.equal(suite.signatureCurve)
  })

  it('decodeCompressPoint', () => {
    const compressPoint = new Uint8Array(prime256v1CompressedFixture)
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const publicKey = VerificationKey.decodeCompressPoint(compressPoint, suite)
    expect(publicKey).to.deep.equal(new Uint8Array(prime256v1PublicFixture))
  })

  it('Precondition: Do not create a VerificationKey for an algorithm suite that does not have an EC named curve.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => new VerificationKey(new Uint8Array(3), suite)).to.throw(
      'Unsupported Algorithm'
    )
  })

  it('Precondition: Do not decode a public key for an algorithm suite that does not have an EC named curve.', () => {
    const compressPoint = new Uint8Array(prime256v1CompressedFixture)
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() =>
      VerificationKey.decodeCompressPoint(compressPoint, suite)
    ).to.throw('Unsupported Algorithm')
  })
})
