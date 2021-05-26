// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env jasmine */

// expect is from karma-jasmine
declare const expect: any //https://jasmine.github.io/api/edge/global.html#expect
import { MultiKeyringWebCrypto } from '@aws-crypto/client-browser'
import {
  AESKey,
  AesKeyInfo,
  KeyInfoTuple,
  KMSKey,
  RSAKey,
  RsaKeyInfo,
} from '@aws-crypto/integration-vectors'
import {
  decryptMaterialsManagerWebCrypto,
  encryptMaterialsManagerWebCrypto,
} from '../src/decrypt_materials_manager_web_crypto'
import { KmsKeyInfo } from '@aws-crypto/integration-vectors'
import {
  validPrivateRSAKey,
  validPublicAESKey,
  validPublicRSAKey,
} from './unitTestConstants'

describe('decrypt_materials_manager_web_crypto', () => {
  const rsaKeyInfo: RsaKeyInfo = {
    'encryption-algorithm': 'rsa',
    'padding-algorithm': 'oaep-mgf1',
    'padding-hash': 'sha1',
    'provider-id': 'mock',
    key: 'mock',
    type: 'raw',
  }
  const pubRsaKey: RSAKey = {
    'key-id': 'mock',
    algorithm: 'rsa',
    bits: 1024,
    decrypt: true,
    encoding: 'pem',
    encrypt: true,
    material: validPublicRSAKey,
    type: 'public',
  }
  const privRsaKey: RSAKey = {
    'key-id': 'mock',
    algorithm: 'rsa',
    bits: 1024,
    decrypt: true,
    encoding: 'pem',
    encrypt: true,
    material: validPrivateRSAKey,
    type: 'private',
  }
  const aesKeyInfo: AesKeyInfo = {
    'encryption-algorithm': 'aes',
    'padding-algorithm': null,
    'provider-id': 'mock',
    key: 'mock',
    type: 'raw',
  }
  const aesKey: AESKey = {
    'key-id': 'mock',
    algorithm: 'aes',
    bits: 128,
    decrypt: true,
    encoding: 'base64',
    encrypt: true,
    material: validPublicAESKey,
    type: 'symmetric',
  }
  const kmsKeyInfo: KmsKeyInfo = {
    type: 'aws-kms',
    key: 'us-west-2-decryptable',
  }
  const kmsKey: KMSKey = {
    decrypt: true,
    encrypt: true,
    type: 'aws-kms',
    'key-id':
      'arn:aws:kms:us-west-2:000000000000:key/mockmock-mock-mock-mock-mockmockmok',
  }
  describe('encryptMaterialsManagerWebCrypto returns a MultiKeyringWebCrypto', () => {
    it('when passed a KMS key', async () => {
      await testMethod(kmsKeyInfo, kmsKey, encryptMaterialsManagerWebCrypto)
    })
    it('when passed a public RSA Key', async () => {
      await testMethod(rsaKeyInfo, pubRsaKey, encryptMaterialsManagerWebCrypto)
    })
    it('when passed a AES Key', async () => {
      await testMethod(aesKeyInfo, aesKey, encryptMaterialsManagerWebCrypto)
    })
  })

  describe('decryptMaterialsManagerWebCrypto returns a MultiKeyringWebCrypto', () => {
    it('when passed a KMS key', async () => {
      await testMethod(kmsKeyInfo, kmsKey, decryptMaterialsManagerWebCrypto)
    })
    it('when passed a private RSA Key', async () => {
      await testMethod(rsaKeyInfo, privRsaKey, decryptMaterialsManagerWebCrypto)
    })
    it('when passed a AES Key', async () => {
      await testMethod(aesKeyInfo, aesKey, decryptMaterialsManagerWebCrypto)
    })
  })
})

// @ts-ignore
async function testMethod(keyInfo, key, method) {
  const multiKeyringWebCrypto: MultiKeyringWebCrypto = await method([
    [keyInfo, key],
  ] as KeyInfoTuple[])
  expect(multiKeyringWebCrypto).to.not.be.undefined
}
