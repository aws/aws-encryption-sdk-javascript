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
  needs,
  WebCryptoCryptographicMaterialsManager,
  MultiKeyringWebCrypto
} from '@aws-crypto/material-management-browser'
import {
  KmsKeyringBrowser,
  KmsWebCryptoClientSupplier, // eslint-disable-line no-unused-vars
  KMS
} from '@aws-crypto/kms-keyring-browser'
import {
  RawAesKeyringWebCrypto,
  WrappingSuiteIdentifier, // eslint-disable-line no-unused-vars
  RawAesWrappingSuiteIdentifier
} from '@aws-crypto/raw-aes-keyring-browser'
import { RawRsaKeyringWebCrypto } from '@aws-crypto/raw-rsa-keyring-browser'
import {
  RsaKeyInfo, // eslint-disable-line no-unused-vars
  AesKeyInfo, // eslint-disable-line no-unused-vars
  KmsKeyInfo, // eslint-disable-line no-unused-vars
  RSAKey, // eslint-disable-line no-unused-vars
  AESKey, // eslint-disable-line no-unused-vars
  KMSKey, // eslint-disable-line no-unused-vars
  KeyInfoTuple // eslint-disable-line no-unused-vars
} from './types'

import { fromBase64 } from '@aws-sdk/util-base64-browser'
// @ts-ignore
import keyto from '@trust/keyto'
declare const credentials: any

const Bits2RawAesWrappingSuiteIdentifier: {[key: number]: WrappingSuiteIdentifier} = {
  128: RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING,
  // 192: RawAesWrappingSuiteIdentifier.AES192_GCM_IV12_TAG16_NO_PADDING,
  256: RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING
}

export async function decryptMaterialsManagerWebCrypto (keyInfos: KeyInfoTuple[]) {
  const children = await Promise.all(keyInfos.map(keyringWebCrypto))
  const keyring = new MultiKeyringWebCrypto({ children })
  return new WebCryptoCryptographicMaterialsManager(keyring)
}

async function keyringWebCrypto ([ info, key ]: KeyInfoTuple) {
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

function kmsKeyring (_keyInfo: KmsKeyInfo, key: KMSKey) {
  const keyIds = [key['key-id']]
  const clientProvider: KmsWebCryptoClientSupplier = (region: string) => {
    return new KMS({ region, credentials })
  }
  return new KmsKeyringBrowser({ keyIds, clientProvider })
}

async function aesKeyring (keyInfo:AesKeyInfo, key: AESKey) {
  const keyName = key['key-id']
  const keyNamespace = keyInfo['provider-id']
  const { encoding, material } = key
  needs(encoding === 'base64', 'Unsupported encoding')
  const rawKey = fromBase64(material)
  if (!Bits2RawAesWrappingSuiteIdentifier[key.bits]) throw new Error('Unsupported right now')
  const wrappingSuite = Bits2RawAesWrappingSuiteIdentifier[key.bits]
  const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(rawKey, wrappingSuite)
  return new RawAesKeyringWebCrypto({ keyName, keyNamespace, masterKey, wrappingSuite })
}

async function rsaKeyring (keyInfo: RsaKeyInfo, key: RSAKey) {
  const keyName = key['key-id']
  const keyNamespace = keyInfo['provider-id']

  const rsaKey = await pem2JWK(keyInfo, key)
  return new RawRsaKeyringWebCrypto({ keyName, keyNamespace, ...rsaKey })
}

async function pem2JWK (keyInfo: RsaKeyInfo, { material, type }: RSAKey) {
  const OAEP_SHA1_MFG1 = 'RSA-OAEP'
  const OAEP_SHA256_MFG1 = 'RSA-OAEP-256'
  const OAEP_SHA384_MFG1 = 'RSA-OAEP-384'
  const OAEP_SHA512_MFG1 = 'RSA-OAEP-512'
  // const RSASSA_PKCS1_V1_5_SHA1 = 'RSASSA-PKCS1-v1_5'

  // @ts-ignore
  const jwk = keyto.from(material, 'pem').toJwk(type)

  const paddingAlgorithm = keyInfo['padding-algorithm']
  const paddingHash = keyInfo['padding-hash']
  if (paddingAlgorithm === 'oaep-mgf1') {
    jwk.alg = paddingHash === 'sha1'
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
