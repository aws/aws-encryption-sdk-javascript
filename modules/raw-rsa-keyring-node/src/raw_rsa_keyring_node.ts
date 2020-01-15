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
  KeyringNode,
  needs,
  NodeEncryptionMaterial, // eslint-disable-line no-unused-vars
  NodeDecryptionMaterial, // eslint-disable-line no-unused-vars
  EncryptedDataKey,
  KeyringTrace, // eslint-disable-line no-unused-vars
  KeyringTraceFlag,
  immutableClass,
  readOnlyProperty,
  unwrapDataKey,
  AwsEsdkKeyObject, // eslint-disable-line no-unused-vars
  NodeAlgorithmSuite // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'

import {
  constants,
  publicEncrypt,
  privateDecrypt,
  randomBytes,
  RsaPublicKey, // eslint-disable-line no-unused-vars
  RsaPrivateKey // eslint-disable-line no-unused-vars
} from 'crypto'

import {
  _onEncrypt,
  _onDecrypt,
  WrapKey, // eslint-disable-line no-unused-vars
  UnwrapKey // eslint-disable-line no-unused-vars
} from '@aws-crypto/raw-keyring'

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

export type RawRsaKeyringNodeInput = {
  keyNamespace: string
  keyName: string
  rsaKey: RsaKey
  padding?: number
  oaepHash?: 'sha1'|'sha256'|'sha512'
}

/* Node supports RSA_OAEP_SHA1_MFG1 by default.
 * It does not support RSA_OAEP_SHA256_MFG1 at this time.
 * Passing RSA_PKCS1_OAEP_PADDING implies RSA_OAEP_SHA1_MFG1.
 */

export class RawRsaKeyringNode extends KeyringNode {
  public keyNamespace!: string
  public keyName!: string
  _wrapKey!: WrapKey<NodeAlgorithmSuite>
  _unwrapKey!: UnwrapKey<NodeAlgorithmSuite>

  constructor (input: RawRsaKeyringNodeInput) {
    super()

    const { rsaKey, keyName, keyNamespace, padding = constants.RSA_PKCS1_OAEP_PADDING, oaepHash } = input
    const { publicKey, privateKey } = rsaKey
    /* Precondition: RsaKeyringNode needs either a public or a private key to operate. */
    needs(publicKey || privateKey, 'No Key provided.')
    /* Precondition: RsaKeyringNode needs identifying information for encrypt and decrypt. */
    needs(keyName && keyNamespace, 'Identifying information must be defined.')

    const _wrapKey = async (material: NodeEncryptionMaterial) => {
      /* Precondition: Public key must be defined to support encrypt. */
      if (!publicKey) throw new Error('No public key defined in constructor.  Encrypt disabled.')
      const { buffer, byteOffset, byteLength } = unwrapDataKey(material.getUnencryptedDataKey())
      const encryptedDataKey = publicEncrypt(
        { key: publicKey, padding, oaepHash } as RsaPublicKey,
        Buffer.from(buffer, byteOffset, byteLength))
      const providerInfo = this.keyName
      const providerId = this.keyNamespace
      const flag = KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      const edk = new EncryptedDataKey({ encryptedDataKey, providerInfo, providerId })
      return material.addEncryptedDataKey(edk, flag)
    }

    const _unwrapKey = async (material: NodeDecryptionMaterial, edk: EncryptedDataKey) => {
      /* Precondition: Private key must be defined to support decrypt. */
      if (!privateKey) throw new Error('No private key defined in constructor.  Decrypt disabled.')

      const trace: KeyringTrace = {
        keyName: this.keyName,
        keyNamespace: this.keyNamespace,
        flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
      }

      const { buffer, byteOffset, byteLength } = edk.encryptedDataKey
      const encryptedDataKey = Buffer.from(buffer, byteOffset, byteLength)
      const unencryptedDataKey = privateDecrypt(
        { key: privateKey, padding, oaepHash } as RsaPrivateKey,
        encryptedDataKey)
      return material.setUnencryptedDataKey(unencryptedDataKey, trace)
    }

    readOnlyProperty(this, 'keyName', keyName)
    readOnlyProperty(this, 'keyNamespace', keyNamespace)
    readOnlyProperty(this, '_wrapKey', _wrapKey)
    readOnlyProperty(this, '_unwrapKey', _unwrapKey)
  }

  _filter ({ providerId, providerInfo }: EncryptedDataKey) {
    const { keyNamespace, keyName } = this
    return providerId === keyNamespace && providerInfo === keyName
  }

  _onEncrypt = _onEncrypt<NodeAlgorithmSuite, RawRsaKeyringNode>(randomBytesAsync)
  _onDecrypt = _onDecrypt<NodeAlgorithmSuite, RawRsaKeyringNode>()
}
immutableClass(RawRsaKeyringNode)

function randomBytesAsync (size: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    randomBytes(size, (err: Error|null, buffer: Buffer) => {
      if (err) return reject(err)
      resolve(buffer)
    })
  })
}
