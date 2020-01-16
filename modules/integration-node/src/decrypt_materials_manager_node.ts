/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  MultiKeyringNode,
  KmsKeyringNode,
  RawAesKeyringNode,
  WrappingSuiteIdentifier, // eslint-disable-line no-unused-vars
  RawAesWrappingSuiteIdentifier,
  RawRsaKeyringNode
} from '@aws-crypto/client-node'
import {
  RsaKeyInfo, // eslint-disable-line no-unused-vars
  AesKeyInfo, // eslint-disable-line no-unused-vars
  KmsKeyInfo, // eslint-disable-line no-unused-vars
  RSAKey, // eslint-disable-line no-unused-vars
  AESKey, // eslint-disable-line no-unused-vars
  KMSKey, // eslint-disable-line no-unused-vars
  KeyInfoTuple // eslint-disable-line no-unused-vars
} from './types'
import { constants } from 'crypto'

const Bits2RawAesWrappingSuiteIdentifier: {[key: number]: WrappingSuiteIdentifier} = {
  128: RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING,
  192: RawAesWrappingSuiteIdentifier.AES192_GCM_IV12_TAG16_NO_PADDING,
  256: RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING
}

export function encryptMaterialsManagerNode (keyInfos: KeyInfoTuple[]) {
  const [generator, ...children] = keyInfos.map(keyringNode)
  return new MultiKeyringNode({ generator, children })
}

export function decryptMaterialsManagerNode (keyInfos: KeyInfoTuple[]) {
  const children = keyInfos.map(keyringNode)
  return new MultiKeyringNode({ children })
}

export function keyringNode ([ info, key ]: KeyInfoTuple) {
  if (info.type === 'aws-kms' && key.type === 'aws-kms') {
    return kmsKeyring(info, key)
  }
  if (info.type === 'raw' && info['encryption-algorithm'] === 'aes' && key.type === 'symmetric') {
    return aesKeyring(info, key)
  }
  if (info.type === 'raw' && info['encryption-algorithm'] === 'rsa' && (key.type === 'public' || key.type === 'private')) {
    return rsaKeyring(info, key)
  }
  throw new Error('Unsupported keyring type')
}

export function kmsKeyring (_keyInfo: KmsKeyInfo, key: KMSKey) {
  const generatorKeyId = key['key-id']
  return new KmsKeyringNode({ generatorKeyId })
}

export function aesKeyring (keyInfo:AesKeyInfo, key: AESKey) {
  const keyName = key['key-id']
  const keyNamespace = keyInfo['provider-id']
  const { encoding, material } = key
  const unencryptedMasterKey = Buffer.alloc(key.bits / 8, material, encoding)
  const wrappingSuite = Bits2RawAesWrappingSuiteIdentifier[key.bits]
  return new RawAesKeyringNode({ keyName, keyNamespace, unencryptedMasterKey, wrappingSuite })
}

export function rsaKeyring (keyInfo: RsaKeyInfo, key: RSAKey) {
  const keyName = key['key-id']
  const keyNamespace = keyInfo['provider-id']
  const rsaKey = key.type === 'private'
    ? { privateKey: key.material }
    : { publicKey: key.material }
  const padding = rsaPadding(keyInfo)
  const oaepHash = keyInfo['padding-hash']
  return new RawRsaKeyringNode({ keyName, keyNamespace, rsaKey, padding, oaepHash })
}

export function rsaPadding (keyInfo: RsaKeyInfo) {
  const paddingAlgorithm = keyInfo['padding-algorithm']
  return paddingAlgorithm === 'pkcs1'
    ? constants.RSA_PKCS1_PADDING
    : constants.RSA_PKCS1_OAEP_PADDING
}

export class NotSupported extends Error {
  code: string
  constructor (message?: string) {
    super(message)
    Object.setPrototypeOf(this, NotSupported.prototype)
    this.code = 'NOT_SUPPORTED'
  }
}
