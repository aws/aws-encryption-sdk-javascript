// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { EncryptionContext } from '@aws-crypto/material-management'
import { Readable } from 'stream'
import { Entry } from 'yauzl'

//START json representation of data in aws-encryption-sdk-test-vectors
interface BaseDecryptTest {
  description?: string
  ciphertext: string
  'master-keys': (
    | RsaKeyInfo
    | AesKeyInfo
    | KmsKeyInfo
    | KmsMrkAwareKeyInfo
    | KmsMrkAwareDiscoveryKeyInfo
  )[]
  'decryption-method'?: string
}

export interface NegativeDecryptTest extends BaseDecryptTest {
  result: { error: { 'error-description': string } }
}

export interface PositiveDecryptTest extends BaseDecryptTest {
  result: { output: { plaintext: string } }
}

export type DecryptTest = NegativeDecryptTest | PositiveDecryptTest
//END json representation of data in aws-encryption-sdk-test-vectors

export interface BaseVectorTest {
  name: string
  description?: string
  keysInfo: KeyInfoTuple[]
  decryptionMethod?: string
}

export interface BaseTestVectorInfo extends BaseVectorTest {
  cipherStream: () => Promise<Readable>
}

export interface PositiveTestVectorInfo extends BaseTestVectorInfo {
  plainTextStream: () => Promise<Readable>
}

export interface NegativeTestVectorInfo extends BaseTestVectorInfo {
  errorDescription: string
}

export type TestVectorInfo = NegativeTestVectorInfo | PositiveTestVectorInfo

export interface DecryptionFixture extends BaseVectorTest {
  cipherFile: string
  cipherText: string
  result: { plainText: string } | { errorDescription: string }
}

export interface TestVectorResult {
  name: string
  result: boolean
  description?: string
  err?: Error
}

export interface StreamEntry extends Entry {
  stream: () => Promise<Readable>
}

interface Manifest {
  type: string
  version: number
}

export interface DecryptManifest extends Manifest {
  type: 'awses-decrypt'
}

interface EncryptManifest extends Manifest {
  type: 'awses-encrypt'
}

export interface DecryptManifestList {
  manifest: DecryptManifest
  client: Client
  keys: string
  tests: { [testName: string]: PositiveDecryptTest | NegativeDecryptTest }
}

export interface EncryptManifestList {
  manifest: EncryptManifest
  client: Client
  keys: string
  plaintexts: { [name: string]: number }
  tests: { [testName: string]: EncryptTest }
}

export interface Client {
  name: string
  version: string
}

interface KeyInfo {
  type: 'aws-kms' | 'raw' | 'aws-kms-mrk-aware' | 'aws-kms-mrk-aware-discovery'
  key: string
}

interface RawKeyInfo extends KeyInfo {
  type: 'raw'
  'provider-id': string
  'encryption-algorithm': 'aes' | 'rsa'
  'padding-algorithm': 'pkcs1' | 'oaep-mgf1' | null
}

export interface RsaKeyInfo extends RawKeyInfo {
  'encryption-algorithm': 'rsa'
  'padding-algorithm': 'pkcs1' | 'oaep-mgf1'
  'padding-hash': 'sha1' | 'sha256' | 'sha384' | 'sha512'
}

export interface AesKeyInfo extends RawKeyInfo {
  'encryption-algorithm': 'aes'
  'padding-algorithm': null
}

export interface KmsKeyInfo extends KeyInfo {
  type: 'aws-kms'
  key: string
}

export interface KmsMrkAwareKeyInfo extends KeyInfo {
  type: 'aws-kms-mrk-aware'
  key: string
}

export interface KmsMrkAwareDiscoveryKeyInfo {
  type: 'aws-kms-mrk-aware-discovery'
  'default-mrk-region': string
  'aws-kms-discovery-filter'?: {
    partition: string
    'account-ids': string[]
  }
}

interface EncryptTest {
  plaintext: string
  algorithm: string
  'frame-size': number
  'encryption-context': EncryptionContext
  'master-keys': (RsaKeyInfo | AesKeyInfo | KmsKeyInfo)[]
}

interface Key {
  encrypt: boolean
  decrypt: boolean
  'key-id': string
}

interface RawKey extends Key {
  algorithm: string
  type: string
  bits: number
  encoding: string
  material: string
}

export interface RSAKey extends RawKey {
  algorithm: 'rsa'
  type: 'public' | 'private'
  bits: number
  encoding: 'pem'
  material: string
}

export interface AESKey extends RawKey {
  algorithm: 'aes'
  type: 'symmetric'
  bits: number
  encoding: 'base64'
  material: string
}

export interface KMSKey extends Key {
  type: 'aws-kms'
  'key-id': string
}

export interface KeyList {
  manifest: Manifest
  keys: { [key: string]: KMSKey | AESKey | RSAKey }
}

export type KeyInfoTuple =
  | [RsaKeyInfo, RSAKey]
  | [AesKeyInfo, AESKey]
  | [KmsKeyInfo, KMSKey]
  | [KmsMrkAwareKeyInfo, KMSKey]
  | [KmsMrkAwareDiscoveryKeyInfo]
