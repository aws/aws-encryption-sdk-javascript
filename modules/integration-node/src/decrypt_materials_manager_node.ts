// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  needs,
  KeyringNode,
  MultiKeyringNode,
  KmsKeyringNode,
  RawAesKeyringNode,
  WrappingSuiteIdentifier,
  RawAesWrappingSuiteIdentifier,
  RawRsaKeyringNode,
  oaepHashSupported,
  buildAwsKmsMrkAwareStrictMultiKeyringNode,
  buildAwsKmsMrkAwareDiscoveryMultiKeyringNode,
} from '@aws-crypto/client-node'
import {
  RsaKeyInfo,
  AesKeyInfo,
  KmsKeyInfo,
  KmsMrkAwareKeyInfo,
  KmsMrkAwareDiscoveryKeyInfo,
  RSAKey,
  AESKey,
  KMSKey,
  KeyInfoTuple,
  buildGetKeyring,
} from '@aws-crypto/integration-vectors'
import { constants } from 'crypto'

const Bits2RawAesWrappingSuiteIdentifier: {
  [key: number]: WrappingSuiteIdentifier
} = {
  128: RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING,
  192: RawAesWrappingSuiteIdentifier.AES192_GCM_IV12_TAG16_NO_PADDING,
  256: RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING,
}

export const keyringNode = buildGetKeyring<KeyringNode>({
  kmsKeyring,
  kmsMrkAwareKeyring,
  kmsMrkAwareDiscoveryKeyring,
  aesKeyring,
  rsaKeyring,
})

export function encryptMaterialsManagerNode(keyInfos: KeyInfoTuple[]) {
  const [generator, ...children] = keyInfos.map(keyringNode)
  return new MultiKeyringNode({ generator, children })
}

export function decryptMaterialsManagerNode(keyInfos: KeyInfoTuple[]) {
  const children = keyInfos.map(keyringNode)
  return new MultiKeyringNode({ children })
}

export function kmsKeyring(_keyInfo: KmsKeyInfo, key: KMSKey) {
  const generatorKeyId = key['key-id']
  return new KmsKeyringNode({ generatorKeyId })
}

export function kmsMrkAwareKeyring(_keyInfo: KmsMrkAwareKeyInfo, key: KMSKey) {
  const generatorKeyId = key['key-id']
  return buildAwsKmsMrkAwareStrictMultiKeyringNode({ generatorKeyId })
}

export function kmsMrkAwareDiscoveryKeyring(
  keyInfo: KmsMrkAwareDiscoveryKeyInfo
) {
  const regions = [keyInfo['default-mrk-region']]
  const { 'aws-kms-discovery-filter': filter } = keyInfo
  const discoveryFilter = filter
    ? { partition: filter.partition, accountIDs: filter['account-ids'] }
    : undefined
  return buildAwsKmsMrkAwareDiscoveryMultiKeyringNode({
    discoveryFilter,
    regions,
  })
}

export function aesKeyring(keyInfo: AesKeyInfo, key: AESKey) {
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

export function rsaKeyring(keyInfo: RsaKeyInfo, key: RSAKey) {
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

export function rsaPadding(keyInfo: RsaKeyInfo) {
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
