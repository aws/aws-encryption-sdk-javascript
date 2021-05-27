// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  needs,
  MultiKeyringNode,
  KmsKeyringNode,
  RawAesKeyringNode,
  WrappingSuiteIdentifier,
  RawAesWrappingSuiteIdentifier,
  RawRsaKeyringNode,
  oaepHashSupported,
} from '@aws-crypto/client-node'
import {
  RsaKeyInfo,
  AesKeyInfo,
  KmsKeyInfo,
  RSAKey,
  AESKey,
  KMSKey,
  KeyInfoTuple,
} from '@aws-crypto/integration-vectors'
import { constants } from 'crypto'

const Bits2RawAesWrappingSuiteIdentifier: {
  [key: number]: WrappingSuiteIdentifier
} = {
  128: RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING,
  192: RawAesWrappingSuiteIdentifier.AES192_GCM_IV12_TAG16_NO_PADDING,
  256: RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING,
}

export function encryptMaterialsManagerNode(
  keyInfos: KeyInfoTuple[]
): MultiKeyringNode {
  const [generator, ...children] = keyInfos.map(keyringNode)
  return new MultiKeyringNode({ generator, children })
}

export function decryptMaterialsManagerNode(
  keyInfos: KeyInfoTuple[]
): MultiKeyringNode {
  const children = keyInfos.map(keyringNode)
  return new MultiKeyringNode({ children })
}

export function keyringNode([info, key]: KeyInfoTuple):
  | KmsKeyringNode
  | RawAesKeyringNode
  | RawRsaKeyringNode {
  if (info.type === 'aws-kms' && key.type === 'aws-kms') {
    return kmsKeyring(info, key)
  }
  if (
    info.type === 'raw' &&
    info['encryption-algorithm'] === 'aes' &&
    key.type === 'symmetric'
  ) {
    return aesKeyring(info, key)
  }
  if (
    info.type === 'raw' &&
    info['encryption-algorithm'] === 'rsa' &&
    (key.type === 'public' || key.type === 'private')
  ) {
    return rsaKeyring(info, key)
  }
  throw new Error('Unsupported keyring type')
}

export function kmsKeyring(_keyInfo: KmsKeyInfo, key: KMSKey): KmsKeyringNode {
  const generatorKeyId = key['key-id']
  return new KmsKeyringNode({ generatorKeyId })
}

export function aesKeyring(
  keyInfo: AesKeyInfo,
  key: AESKey
): RawAesKeyringNode {
  const keyName = key['key-id']
  const keyNamespace = keyInfo['provider-id']
  const { encoding, material } = key
  const unencryptedMasterKey = Buffer.alloc(key.bits / 8, material, encoding)
  const wrappingSuite = Bits2RawAesWrappingSuiteIdentifier[key.bits]
  return new RawAesKeyringNode({
    keyName,
    keyNamespace,
    unencryptedMasterKey,
    wrappingSuite,
  })
}

export function rsaKeyring(
  keyInfo: RsaKeyInfo,
  key: RSAKey
): RawRsaKeyringNode {
  const keyName = key['key-id']
  const keyNamespace = keyInfo['provider-id']
  const rsaKey =
    key.type === 'private'
      ? { privateKey: key.material }
      : { publicKey: key.material }
  const { padding, oaepHash } = rsaPadding(keyInfo)
  return new RawRsaKeyringNode({
    keyName,
    keyNamespace,
    rsaKey,
    padding,
    oaepHash,
  })
}

interface PaddingTuple {
  padding: number
  oaepHash?: 'sha1' | 'sha256' | 'sha384' | 'sha512'
}

export function rsaPadding(keyInfo: RsaKeyInfo): PaddingTuple {
  if (keyInfo['padding-algorithm'] === 'pkcs1')
    return { padding: constants.RSA_PKCS1_PADDING }
  const padding = constants.RSA_PKCS1_OAEP_PADDING
  const oaepHash = keyInfo['padding-hash']
  needs(oaepHashSupported || oaepHash === 'sha1', 'Not supported at this time.')
  return { padding, oaepHash }
}

export class NotSupported extends Error {
  code: string
  constructor(message?: string) {
    super(message)
    Object.setPrototypeOf(this, NotSupported.prototype)
    this.code = 'NOT_SUPPORTED'
  }
}
