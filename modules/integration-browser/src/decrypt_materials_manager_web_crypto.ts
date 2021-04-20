// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  needs,
  KeyringWebCrypto,
  MultiKeyringWebCrypto,
  KmsKeyringBrowser,
  KmsWebCryptoClientSupplier,
  KMS,
  RawAesKeyringWebCrypto,
  WrappingSuiteIdentifier,
  RawAesWrappingSuiteIdentifier,
  RawRsaKeyringWebCrypto,
  buildAwsKmsMrkAwareStrictMultiKeyringBrowser,
  buildAwsKmsMrkAwareDiscoveryMultiKeyringBrowser,
} from '@aws-crypto/client-browser'
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

import { fromBase64 } from '@aws-sdk/util-base64-browser'
// @ts-ignore
import keyto from '@trust/keyto'
// credentials is from '@aws-sdk/karma-credential-loader'
declare const credentials: any

const Bits2RawAesWrappingSuiteIdentifier: {
  [key: number]: WrappingSuiteIdentifier
} = {
  128: RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING,
  /* Browsers do not support 192 Bit keys.
   * Leaving this here to make sure this is clear.
   *192: RawAesWrappingSuiteIdentifier.AES192_GCM_IV12_TAG16_NO_PADDING,
   */
  256: RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING,
}

const keyringWebCrypto = buildGetKeyring<Promise<KeyringWebCrypto>>({
  kmsKeyring,
  kmsMrkAwareKeyring,
  kmsMrkAwareDiscoveryKeyring,
  aesKeyring,
  rsaKeyring,
})

export async function encryptMaterialsManagerWebCrypto(
  keyInfos: KeyInfoTuple[]
): Promise<MultiKeyringWebCrypto> {
  const [generator, ...children] = await Promise.all(
    keyInfos.map(keyringWebCrypto)
  )
  return new MultiKeyringWebCrypto({ generator, children })
}

export async function decryptMaterialsManagerWebCrypto(
  keyInfos: KeyInfoTuple[]
): Promise<MultiKeyringWebCrypto> {
  const children = await Promise.all(keyInfos.map(keyringWebCrypto))
  return new MultiKeyringWebCrypto({ children })
}

async function kmsKeyring(_keyInfo: KmsKeyInfo, key: KMSKey) {
  const generatorKeyId = key['key-id']
  const clientProvider: KmsWebCryptoClientSupplier = (region: string) => {
    return new KMS({ region, credentials })
  }
  return new KmsKeyringBrowser({ generatorKeyId, clientProvider })
}

async function kmsMrkAwareKeyring(_keyInfo: KmsMrkAwareKeyInfo, key: KMSKey) {
  const generatorKeyId = key['key-id']
  const clientProvider: KmsWebCryptoClientSupplier = (region: string) => {
    return new KMS({ region, credentials })
  }
  return buildAwsKmsMrkAwareStrictMultiKeyringBrowser({
    generatorKeyId,
    clientProvider,
  })
}

async function kmsMrkAwareDiscoveryKeyring(
  keyInfo: KmsMrkAwareDiscoveryKeyInfo
) {
  const regions = [keyInfo['default-mrk-region']]
  const { 'aws-kms-discovery-filter': filter } = keyInfo
  const discoveryFilter = filter
    ? { partition: filter.partition, accountIDs: filter['account-ids'] }
    : undefined
  const clientProvider: KmsWebCryptoClientSupplier = (region: string) => {
    return new KMS({ region, credentials })
  }
  return buildAwsKmsMrkAwareDiscoveryMultiKeyringBrowser({
    discoveryFilter,
    regions,
    clientProvider,
  })
}

async function aesKeyring(keyInfo: AesKeyInfo, key: AESKey) {
  const keyName = key['key-id']
  const keyNamespace = keyInfo['provider-id']
  const { encoding, material } = key
  needs(encoding === 'base64', 'Unsupported encoding')
  const rawKey = fromBase64(material)
  if (!Bits2RawAesWrappingSuiteIdentifier[key.bits])
    throw new Error('Unsupported right now')
  const wrappingSuite = Bits2RawAesWrappingSuiteIdentifier[key.bits]
  const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(
    rawKey,
    wrappingSuite
  )
  return new RawAesKeyringWebCrypto({
    keyName,
    keyNamespace,
    masterKey,
    wrappingSuite,
  })
}

async function rsaKeyring(keyInfo: RsaKeyInfo, key: RSAKey) {
  const keyName = key['key-id']
  const keyNamespace = keyInfo['provider-id']

  const rsaKey = await pem2JWK(keyInfo, key)
  return new RawRsaKeyringWebCrypto({ keyName, keyNamespace, ...rsaKey })
}

async function pem2JWK(keyInfo: RsaKeyInfo, { material, type }: RSAKey) {
  const OAEP_SHA1_MFG1 = 'RSA-OAEP'
  const OAEP_SHA256_MFG1 = 'RSA-OAEP-256'
  const OAEP_SHA384_MFG1 = 'RSA-OAEP-384'
  const OAEP_SHA512_MFG1 = 'RSA-OAEP-512'
  /* Browsers do not support PKCS1.
   * Leaving this here to make sure this is clear.
   * const RSASSA_PKCS1_V1_5_SHA1 = 'RSASSA-PKCS1-v1_5'
   */

  // @ts-ignore
  const jwk = keyto.from(material, 'pem').toJwk(type)

  const paddingAlgorithm = keyInfo['padding-algorithm']
  const paddingHash = keyInfo['padding-hash']
  if (paddingAlgorithm === 'oaep-mgf1') {
    jwk.alg =
      paddingHash === 'sha1'
        ? OAEP_SHA1_MFG1
        : paddingHash === 'sha256'
        ? OAEP_SHA256_MFG1
        : paddingHash === 'sha384'
        ? OAEP_SHA384_MFG1
        : paddingHash === 'sha512'
        ? OAEP_SHA512_MFG1
        : false
  } else if (paddingAlgorithm === 'pkcs1') {
    throw new Error('Unsupported right now')
  }

  if (type === 'public') {
    const publicKey = await RawRsaKeyringWebCrypto.importPublicKey(jwk)
    return { publicKey }
  }

  if (type === 'private') {
    const privateKey = await RawRsaKeyringWebCrypto.importPrivateKey(jwk)
    return { privateKey }
  }

  throw new Error('Unknown type')
}
