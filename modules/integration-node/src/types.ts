// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { EncryptionContext } from '@aws-crypto/client-node' // eslint-disable-line no-unused-vars

export interface DecryptManifestList {
  manifest: DecryptManifest
  client: Client
  keys: string
  tests: {[testName: string]: DecryptTest}
}

export interface EncryptManifestList {
  manifest: EncryptManifest
  keys: string
  plaintexts: {[name: string]: number}
  tests: {[testName: string]: EncryptTest}
}

export interface KeyList {
  manifest: Manifest
  keys: {[key: string]: (KMSKey|AESKey|RSAKey)}
}

interface Manifest {
  type: string
  version: number
}

interface DecryptManifest extends Manifest {
  type: 'awses-decrypt'
}

interface EncryptManifest extends Manifest {
  type: 'awses-encrypt'
}

interface Client {
  name: string
  version: string
}

interface KeyInfo {
  type: 'aws-kms'|'raw'
  key: string
}

interface RawKeyInfo extends KeyInfo {
  type: 'raw',
  'provider-id': string
  'encryption-algorithm': 'aes'|'rsa',
  'padding-algorithm': 'pkcs1'|'oaep-mgf1'|null
}

export interface RsaKeyInfo extends RawKeyInfo {
  'encryption-algorithm': 'rsa',
  'padding-algorithm': 'pkcs1'|'oaep-mgf1'
  'padding-hash'?: 'sha1'|'sha256'|'sha384'|'sha512'
}

export interface AesKeyInfo extends RawKeyInfo {
  'encryption-algorithm': 'aes'
  'padding-algorithm': null
}

export interface KmsKeyInfo extends KeyInfo {
  type: 'aws-kms'
  key: string
}

interface EncryptTest {
  plaintext: string
  algorithm: string
  'frame-size': number
  'encryption-context': EncryptionContext
  'master-keys': (RsaKeyInfo|AesKeyInfo|KmsKeyInfo)[]
}

interface DecryptTest {
  plaintext: string
  ciphertext: string
  'master-keys': (RsaKeyInfo|AesKeyInfo|KmsKeyInfo)[]
}

interface Key {
  'encrypt': boolean
  'decrypt': boolean
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
  type: 'public'|'private'
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

export type KeyInfoTuple = [RsaKeyInfo, RSAKey] | [AesKeyInfo, AESKey] | [KmsKeyInfo, KMSKey]
