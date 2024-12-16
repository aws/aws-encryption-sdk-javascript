// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from 'crypto'
import {
  wrapAad,
  destructureCiphertext,
  serializeEncryptionContext,
  unwrapEncryptedDataKey,
  wrapPlaintextDataKey,
} from '../src/kms_hkeyring_node_helpers'
import { expect } from 'chai'
import { PROVIDER_ID_HIERARCHY_AS_BYTES } from '../src/constants'
import { ALG_SUITES } from './fixtures'
import {
  NodeBranchKeyMaterial,
  NodeDecryptionMaterial,
  NodeEncryptionMaterial,
} from '@aws-crypto/material-management'
import { v4 } from 'uuid'

describe('KmsHierarchicalKeyRingNode: helpers', () => {
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ciphertext
  //= type=test
  //# The following table describes the fields that form the ciphertext for this keyring.
  //# The bytes are appended in the order shown.
  //# The Encryption Key is variable.
  //# It will be whatever length is represented by the algorithm suite.
  //# Because all the other values are constant,
  //# this variability in the encryption key does not impact the format.
  //# | Field              | Length (bytes) | Interpreted as |
  //# | ------------------ | -------------- | -------------- |
  //# | Salt               | 16             | bytes          |
  //# | IV                 | 12             | bytes          |
  //# | Version            | 16             | bytes          |
  //# | Encrypted Key      | Variable       | bytes          |
  //# | Authentication Tag | 16             | bytes          |
  describe('Ciphertext destructuring', () => {
    it('All parts destructured correctly for all algorithm suites', () => {
      for (const algSuite of ALG_SUITES) {
        const actualSalt = randomBytes(16)
        const actualIv = randomBytes(12)
        const actualBranchKeyVersionAsBytesCompressed = randomBytes(16)
        const actualEncryptedDataKey = randomBytes(algSuite.keyLengthBytes)
        const actualAuthTag = randomBytes(16)
        const ciphertext = Buffer.concat([
          actualSalt,
          actualIv,
          actualBranchKeyVersionAsBytesCompressed,
          actualEncryptedDataKey,
          actualAuthTag,
        ])

        // all parts correct
        const {
          salt,
          iv,
          branchKeyVersionAsBytesCompressed,
          encryptedDataKey,
          authTag,
        } = destructureCiphertext(ciphertext, algSuite)

        expect(salt).to.deep.equal(actualSalt)
        expect(iv).to.deep.equal(actualIv)
        expect(branchKeyVersionAsBytesCompressed).to.deep.equal(
          actualBranchKeyVersionAsBytesCompressed
        )
        expect(encryptedDataKey).to.deep.equal(actualEncryptedDataKey)
        expect(authTag).to.deep.equal(actualAuthTag)

        // expect error to destructure a bad length ciphertext
        const badEncryptedDataKey = randomBytes(algSuite.keyLengthBytes + 1)
        const badCiphertext = Buffer.concat([
          actualSalt,
          actualIv,
          actualBranchKeyVersionAsBytesCompressed,
          badEncryptedDataKey,
          actualAuthTag,
        ])
        expect(() => destructureCiphertext(badCiphertext, algSuite)).to.throw(
          `The encrypted data key ciphertext must be ${
            badCiphertext.length - 1
          } bytes long`
        )
      }
    })
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad
  //= type=test
  //# To Encrypt and Decrypt the `wrappedDerivedBranchKey` the keyring MUST include the following values as part of the AAD for
  //# the AES Encrypt/Decrypt calls.
  //# To construct the AAD, the keyring MUST concatenate the following values
  //# 1. "aws-kms-hierarchy" as UTF8 Bytes
  //# 1. Value of `branch-key-id` as UTF8 Bytes
  //# 1. [version](../structures.md#branch-key-version) as Bytes
  //# 1. [encryption context](structures.md#encryption-context-1) from the input
  //#    [encryption materials](../structures.md#encryption-materials) according to the [encryption context serialization specification](../structures.md#serialization).
  //# | Field               | Length (bytes) | Interpreted as                                       |
  //# | ------------------- | -------------- | ---------------------------------------------------- |
  //# | "aws-kms-hierarchy" | 17             | UTF-8 Encoded                                        |
  //# | branch-key-id       | Variable       | UTF-8 Encoded                                        |
  //# | version             | 16             | Bytes                                                |
  //# | encryption context  | Variable       | [Encryption Context](../structures.md#serialization) |
  //# If the keyring cannot serialize the encryption context, the operation MUST fail.
  describe('AAD construction', () => {
    const branchKeyIdAsBytes = Buffer.from('myId', 'utf-8')
    const branchKeyVersionAsBytes = randomBytes(16)
    const encryptionContext = {
      key: 'value',
    }

    it('Precondition: Branch key version must be 16 bytes ', () => {
      const badVersion = randomBytes(15)
      expect(() =>
        wrapAad(branchKeyIdAsBytes, badVersion, encryptionContext)
      ).to.throw('Branch key version must be 16 bytes')
    })

    it('Failed encryption context serialization', () => {
      const unserializeableEc = {
        1: [],
        4: {},
        '': undefined,
      }

      expect(() =>
        wrapAad(
          branchKeyIdAsBytes,
          branchKeyVersionAsBytes,
          unserializeableEc as any
        )
      ).to.throw()
    })

    it('Ensure AAD structure', () => {
      const wrappedAad = wrapAad(
        branchKeyIdAsBytes,
        branchKeyVersionAsBytes,
        encryptionContext
      )

      let startIdx = 0
      expect(wrappedAad.subarray(startIdx, startIdx + 17)).to.deep.equal(
        PROVIDER_ID_HIERARCHY_AS_BYTES
      )

      startIdx += 17
      expect(
        wrappedAad.subarray(startIdx, startIdx + branchKeyIdAsBytes.length)
      ).to.deep.equal(branchKeyIdAsBytes)

      startIdx += branchKeyIdAsBytes.length
      expect(
        wrappedAad.subarray(startIdx, startIdx + branchKeyVersionAsBytes.length)
      ).to.deep.equal(branchKeyVersionAsBytes)

      startIdx += branchKeyVersionAsBytes.length
      const expectedAad = serializeEncryptionContext(encryptionContext).slice(2)
      expect(wrappedAad.subarray(startIdx)).to.deep.equal(expectedAad)
    })
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
  //= type=test
  //# To derive and encrypt a data key the keyring will follow the same key derivation and encryption as [AWS KMS](https://rwc.iacr.org/2018/Slides/Gueron.pdf).
  //# The hierarchical keyring MUST:
  //# 1. Generate a 16 byte random `salt` using a secure source of randomness
  //# 1. Generate a 12 byte random `IV` using a secure source of randomness
  //# 1. Use a [KDF in Counter Mode with a Pseudo Random Function with HMAC SHA 256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf) to derive a 32 byte `derivedBranchKey` data key with the following inputs:
  //#    - Use the `salt` as the salt.
  //#    - Use the branch key as the `key`.
  //#    - Use the UTF8 Encoded value "aws-kms-hierarchy" as the label.
  //# 1. Encrypt a plaintext data key with the `derivedBranchKey` using `AES-GCM-256` with the following inputs:
  //#    - MUST use the `derivedBranchKey` as the AES-GCM cipher key.
  //#    - MUST use the plain text data key that will be wrapped by the `derivedBranchKey` as the AES-GCM message.
  //#    - MUST use the derived `IV` as the AES-GCM IV.
  //#    - MUST use an authentication tag byte of length 16.
  //#    - MUST use the serialized [AAD](#branch-key-wrapping-and-unwrapping-aad) as the AES-GCM AAD.
  //# If OnEncrypt fails to do any of the above, OnEncrypt MUST fail.
  describe('Wrapping plaintext data key', () => {
    it('The ciphertext can be deciphered for all algorithm suites', () => {
      for (const algSuite of ALG_SUITES) {
        const expectedPdk = randomBytes(algSuite.keyLengthBytes)
        const branchKey = Buffer.alloc(32)
        const branchKeyId = 'myBranchKey'
        const branchKeyVersion = v4()
        const encryptionContext = { key: 'value' }
        const branchKeyMaterial = new NodeBranchKeyMaterial(
          branchKey,
          branchKeyId,
          branchKeyVersion,
          encryptionContext
        )
        const encryptionMaterial = new NodeEncryptionMaterial(
          algSuite,
          encryptionContext
        )
        const decryptionMaterial = new NodeDecryptionMaterial(
          algSuite,
          encryptionContext
        )

        const actualPdk = unwrapEncryptedDataKey(
          wrapPlaintextDataKey(
            expectedPdk,
            branchKeyMaterial,
            encryptionMaterial
          ),
          branchKeyMaterial,
          decryptionMaterial
        )
        expect(actualPdk).to.deep.equal(expectedPdk)
      }
    })
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
  //= type=test
  //# To decrypt an encrypted data key with a branch key, the hierarchical keyring MUST:
  //# 1. Deserialize the 16 byte random `salt` from the [edk ciphertext](../structures.md#ciphertext).
  //# 1. Deserialize the 12 byte random `IV` from the [edk ciphertext](../structures.md#ciphertext).
  //# 1. Deserialize the 16 byte `version` from the [edk ciphertext](../structures.md#ciphertext).
  //# 1. Deserialize the `encrypted key` from the [edk ciphertext](../structures.md#ciphertext).
  //# 1. Deserialize the `authentication tag` from the [edk ciphertext](../structures.md#ciphertext).
  //# 1. Use a [KDF in Counter Mode with a Pseudo Random Function with HMAC SHA 256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf) to derive
  //#    the 32 byte `derivedBranchKey` data key with the following inputs:
  //#    - Use the `salt` as the salt.
  //#    - Use the branch key as the `key`.
  //# 1. Decrypt the encrypted data key with the `derivedBranchKey` using `AES-GCM-256` with the following inputs:
  //#    - It MUST use the `encrypted key` obtained from deserialization as the AES-GCM input ciphertext.
  //#    - It MUST use the `authentication tag` obtained from deserialization as the AES-GCM input authentication tag.
  //#    - It MUST use the `derivedBranchKey` as the AES-GCM cipher key.
  //#    - It MUST use the `IV` obtained from deserialization as the AES-GCM input IV.
  //#    - It MUST use the serialized [encryption context](#branch-key-wrapping-and-unwrapping-aad) as the AES-GCM AAD.
  //# If OnDecrypt fails to do any of the above, OnDecrypt MUST fail.
  describe('Encrypted data key unwrapping', () => {
    it('Error with creating the decipher for all algorithm suites', () => {
      for (const algSuite of ALG_SUITES) {
        // create a ciphertext that can be destructured but not deciphered
        const ciphertext = randomBytes(
          16 + 12 + 16 + algSuite.keyLengthBytes + 16
        )
        const branchKey = Buffer.alloc(32)
        const branchKeyId = 'myBranchKey'
        const branchKeyVersion = v4()
        const encryptionContext = { key: 'value' }
        const branchKeyMaterial = new NodeBranchKeyMaterial(
          branchKey,
          branchKeyId,
          branchKeyVersion,
          encryptionContext
        )
        const decryptionMaterial = new NodeDecryptionMaterial(
          algSuite,
          encryptionContext
        )

        expect(() =>
          unwrapEncryptedDataKey(
            ciphertext,
            branchKeyMaterial,
            decryptionMaterial
          )
        ).to.throw('Unsupported state or unable to authenticate data')
      }
    })
  })
})
