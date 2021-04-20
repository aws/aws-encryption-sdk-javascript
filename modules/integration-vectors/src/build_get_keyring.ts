// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KeyInfoTuple,
  RsaKeyInfo,
  AesKeyInfo,
  KmsKeyInfo,
  KmsMrkAwareKeyInfo,
  KmsMrkAwareDiscoveryKeyInfo,
  RSAKey,
  AESKey,
  KMSKey,
} from './types'

export function buildGetKeyring<K>({
  kmsKeyring,
  kmsMrkAwareKeyring,
  kmsMrkAwareDiscoveryKeyring,
  aesKeyring,
  rsaKeyring,
}: {
  kmsKeyring(keyInfo: KmsKeyInfo, key: KMSKey): K
  kmsMrkAwareKeyring(keyInfo: KmsMrkAwareKeyInfo, key: KMSKey): K
  kmsMrkAwareDiscoveryKeyring(keyInfo: KmsMrkAwareDiscoveryKeyInfo): K
  aesKeyring(keyInfo: AesKeyInfo, key: AESKey): K
  rsaKeyring(keyInfo: RsaKeyInfo, key: RSAKey): K
}): (info: KeyInfoTuple) => K {
  return function getKeyring([info, key]: KeyInfoTuple): K {
    if (info.type === 'aws-kms' && key && key.type === 'aws-kms') {
      return kmsKeyring(info, key)
    }

    if (info.type === 'aws-kms-mrk-aware' && key && key.type === 'aws-kms') {
      return kmsMrkAwareKeyring(info, key)
    }

    if (info.type === 'aws-kms-mrk-aware-discovery' && !key) {
      return kmsMrkAwareDiscoveryKeyring(info)
    }

    if (
      info.type === 'raw' &&
      info['encryption-algorithm'] === 'aes' &&
      key &&
      key.type === 'symmetric'
    ) {
      return aesKeyring(info, key)
    }

    if (
      info.type === 'raw' &&
      info['encryption-algorithm'] === 'rsa' &&
      key &&
      (key.type === 'public' || key.type === 'private')
    ) {
      return rsaKeyring(info, key)
    }

    throw new Error('Unsupported keyring type')
  }
}
