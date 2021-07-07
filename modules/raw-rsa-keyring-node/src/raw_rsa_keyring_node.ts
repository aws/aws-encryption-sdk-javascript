// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KeyringNode,
  needs,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  EncryptedDataKey,
  KeyringTrace,
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  unwrapDataKey,
  AwsEsdkKeyObject,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'

import {
  constants,
  publicEncrypt,
  privateDecrypt,
  randomBytes,
  RsaPublicKey,
  RsaPrivateKey,
} from 'crypto'

import {
  _onEncrypt,
  _onDecrypt,
  WrapKey,
  UnwrapKey,
} from '@aws-crypto/raw-keyring'

import { oaepHashSupported } from './oaep_hash_supported'

/* Interface question:
 * When creating a keyring being able to define
 * if the keyring can be used for encrypt/decrypt/both
 * is a useful thing.
 * Since RSA public keys can be derived from the private key
 * what is the best way to signal the keyring usage?
 * I have elected to explicitly pass public/private keys.
 * I could have use the private key for publicEncrypt
 * or more complicated options...  Thoughts?
 */
interface RsaKey {
  publicKey?: string | Buffer | AwsEsdkKeyObject
  privateKey?: string | Buffer | AwsEsdkKeyObject
}

export type OaepHash = 'sha1' | 'sha256' | 'sha384' | 'sha512' | undefined
const supportedOaepHash: OaepHash[] = [
  'sha1',
  'sha256',
  'sha384',
  'sha512',
  undefined,
]

export type RawRsaKeyringNodeInput = {
  keyNamespace: string
  keyName: string
  rsaKey: RsaKey
  padding?: number
  oaepHash?: OaepHash
}

export class RawRsaKeyringNode extends KeyringNode {
  public declare keyNamespace: string
  public declare keyName: string
  declare _wrapKey: WrapKey<NodeAlgorithmSuite>
  declare _unwrapKey: UnwrapKey<NodeAlgorithmSuite>

  constructor(input: RawRsaKeyringNodeInput) {
    super()

    const {
      rsaKey,
      keyName,
      keyNamespace,
      padding = constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash,
    } = input
    const { publicKey, privateKey } = rsaKey
    /* Precondition: RsaKeyringNode needs either a public or a private key to operate. */
    needs(publicKey || privateKey, 'No Key provided.')
    /* Precondition: RsaKeyringNode needs identifying information for encrypt and decrypt. */
    needs(keyName && keyNamespace, 'Identifying information must be defined.')
    /* Precondition: The AWS ESDK only supports specific hash values for OAEP padding. */
    needs(
      padding === constants.RSA_PKCS1_OAEP_PADDING
        ? oaepHashSupported
          ? supportedOaepHash.includes(oaepHash)
          : !oaepHash || oaepHash === 'sha1'
        : !oaepHash,
      'Unsupported oaepHash'
    )

    const _wrapKey = async (material: NodeEncryptionMaterial) => {
      /* Precondition: Public key must be defined to support encrypt. */
      if (!publicKey)
        throw new Error(
          'No public key defined in constructor.  Encrypt disabled.'
        )
      const { buffer, byteOffset, byteLength } = unwrapDataKey(
        material.getUnencryptedDataKey()
      )
      const encryptedDataKey = publicEncrypt(
        { key: publicKey, padding, oaepHash } as RsaPublicKey,
        Buffer.from(buffer, byteOffset, byteLength)
      )
      const providerInfo = this.keyName
      const providerId = this.keyNamespace
      const flag = KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      const edk = new EncryptedDataKey({
        encryptedDataKey,
        providerInfo,
        providerId,
      })
      return material.addEncryptedDataKey(edk, flag)
    }

    const _unwrapKey = async (
      material: NodeDecryptionMaterial,
      edk: EncryptedDataKey
    ) => {
      /* Precondition: Private key must be defined to support decrypt. */
      if (!privateKey)
        throw new Error(
          'No private key defined in constructor.  Decrypt disabled.'
        )

      const trace: KeyringTrace = {
        keyName: this.keyName,
        keyNamespace: this.keyNamespace,
        flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
      }

      const { buffer, byteOffset, byteLength } = edk.encryptedDataKey
      const encryptedDataKey = Buffer.from(buffer, byteOffset, byteLength)
      const unencryptedDataKey = privateDecrypt(
        { key: privateKey, padding, oaepHash } as RsaPrivateKey,
        encryptedDataKey
      )
      return material.setUnencryptedDataKey(unencryptedDataKey, trace)
    }

    readOnlyProperty(this, 'keyName', keyName)
    readOnlyProperty(this, 'keyNamespace', keyNamespace)
    readOnlyProperty(this, '_wrapKey', _wrapKey)
    readOnlyProperty(this, '_unwrapKey', _unwrapKey)
  }

  _filter({ providerId, providerInfo }: EncryptedDataKey) {
    const { keyNamespace, keyName } = this
    return providerId === keyNamespace && providerInfo === keyName
  }

  _onEncrypt = _onEncrypt<NodeAlgorithmSuite, RawRsaKeyringNode>(
    randomBytesAsync
  )
  _onDecrypt = _onDecrypt<NodeAlgorithmSuite, RawRsaKeyringNode>()
}
immutableClass(RawRsaKeyringNode)

async function randomBytesAsync(size: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    randomBytes(size, (err: Error | null, buffer: Buffer) => {
      if (err) return reject(err)
      resolve(buffer)
    })
  })
}
