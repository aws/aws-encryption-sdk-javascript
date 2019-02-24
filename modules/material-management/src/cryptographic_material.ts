/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import {MixedBackendCryptoKey} from './types'
import {EncryptedDataKey} from './encrypted_data_key'
import {SignatureKey, VerificationKey} from './signature_key'
import {frozenClass, readOnlyProperty} from './immutable_class'
import {KeyringTrace} from './keyring_trace'
import { AlgorithmSuite } from './algorithm_suites';
import { NodeAlgorithmSuite } from './node_algorithms';
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms'

/*
 * This public interface to the CryptographicMaterial object is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 * 
 * The CryptographicMaterial's purpose is to bind together all the required elements for
 * encrypting or decrypting a payload.
 * The functional data key (unencrypted or CryptoKey) is the most sensitive data and needs to
 * be protected.  The longer this data persists in memory the 
 * greater the opportunity to be invalidated.  Because
 * a Caching CMM exists is it important to insure that the
 * unencrypted data key and it's meta data can not be manipulated,
 * and that the unencrypted data key can be zeroed when
 * it is no longer needed.
 */

export interface CryptographicMaterial {
  suite: AlgorithmSuite
  setUnencryptedDataKey: (dataKey: Uint8Array) => CryptographicMaterial
  getUnencryptedDataKey: () => Uint8Array
  zeroUnencryptedDataKey: () => CryptographicMaterial
  hasUnencryptedDataKey: boolean
  unencryptedDataKeyLength: number
  keyringTrace: KeyringTrace[]
}

export interface EncryptionMaterial extends CryptographicMaterial {
  encryptedDataKeys: EncryptedDataKey[]
  addEncryptedDataKey: (...encryptedDataKeys: EncryptedDataKey[]) => EncryptionMaterial
  setSignatureKey: (key: SignatureKey) => EncryptionMaterial
  signatureKey?: SignatureKey
}

export interface DecryptionMaterial extends CryptographicMaterial {
  setVerificationKey: (key: VerificationKey) => DecryptionMaterial
  verificationKey?: VerificationKey
}

export interface WebCryptoMaterial extends CryptographicMaterial {
  setCryptoKey: (dataKey: CryptoKey|MixedBackendCryptoKey) => WebCryptoMaterial
  getCryptoKey: () => CryptoKey|MixedBackendCryptoKey
}

export class NodeEncryptionMaterial implements Readonly<EncryptionMaterial> {
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array) => NodeEncryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => NodeEncryptionMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  encryptedDataKeys!: EncryptedDataKey[]
  addEncryptedDataKey!: (...encryptedDataKeys: EncryptedDataKey[]) => NodeEncryptionMaterial
  setSignatureKey!: (key: SignatureKey) => NodeEncryptionMaterial
  signatureKey?: SignatureKey
  constructor(suite: NodeAlgorithmSuite) {
    /* Precondition: suite is NodeAlgorithmSuite */
    if (!(suite instanceof NodeAlgorithmSuite)) throw new Error('')
    this.suite = suite
    decorateCryptographicMaterial<NodeEncryptionMaterial>(this)
    decorateEncryptionMaterial<NodeEncryptionMaterial>(this)
    Object.setPrototypeOf(this, NodeEncryptionMaterial.prototype)
    Object.freeze(this)
  }
}
frozenClass(NodeEncryptionMaterial)

export class NodeDecryptionMaterial implements Readonly<DecryptionMaterial> {
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array) => NodeEncryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => NodeEncryptionMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  setVerificationKey!: (key: VerificationKey) => DecryptionMaterial
  verificationKey?: VerificationKey
  constructor(suite: NodeAlgorithmSuite, unencryptedDataKey: Uint8Array) {
    /* Precondition: suite is NodeAlgorithmSuite */
    if (!(suite instanceof NodeAlgorithmSuite)) throw new Error('')
    this.suite = suite
    decorateCryptographicMaterial<NodeDecryptionMaterial>(this)
    decorateDecryptionMaterial<NodeDecryptionMaterial>(this)
    this.setUnencryptedDataKey(unencryptedDataKey)
    Object.setPrototypeOf(this, NodeDecryptionMaterial.prototype)
    Object.freeze(this)
  }
}
frozenClass(NodeDecryptionMaterial)

export class WebCryptoEncryptionMaterial implements Readonly<EncryptionMaterial>, Readonly<WebCryptoMaterial> {
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array) => NodeEncryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => NodeEncryptionMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  encryptedDataKeys!: EncryptedDataKey[]
  addEncryptedDataKey!: (...encryptedDataKeys: EncryptedDataKey[]) => NodeEncryptionMaterial
  setSignatureKey!: (key: SignatureKey) => NodeEncryptionMaterial
  signatureKey?: SignatureKey
  setCryptoKey!: (dataKey: CryptoKey|MixedBackendCryptoKey) => WebCryptoMaterial
  getCryptoKey!: () => CryptoKey|MixedBackendCryptoKey
  constructor(suite: WebCryptoAlgorithmSuite) {
    /* Precondition: suite is WebCryptoAlgorithmSuite */
    if (!(suite instanceof WebCryptoAlgorithmSuite)) throw new Error('')
    this.suite = suite
    decorateCryptographicMaterial<WebCryptoEncryptionMaterial>(this)
    decorateEncryptionMaterial<WebCryptoEncryptionMaterial>(this)
    decorateWebCryptoMaterial<WebCryptoEncryptionMaterial>(this)
    Object.setPrototypeOf(this, WebCryptoEncryptionMaterial.prototype)
    Object.freeze(this)
  }
}
frozenClass(WebCryptoEncryptionMaterial)

export class WebCryptoDecryptionMaterial implements Readonly<DecryptionMaterial>, Readonly<WebCryptoMaterial> {
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array) => NodeEncryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => NodeEncryptionMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  setVerificationKey!: (key: VerificationKey) => DecryptionMaterial
  verificationKey?: VerificationKey
  setCryptoKey!: (dataKey: CryptoKey|MixedBackendCryptoKey) => WebCryptoMaterial
  getCryptoKey!: () => CryptoKey|MixedBackendCryptoKey
  constructor(suite: WebCryptoAlgorithmSuite, unencryptedDataKey: Uint8Array) {
    /* Precondition: suite is WebCryptoAlgorithmSuite */
    if (!(suite instanceof WebCryptoAlgorithmSuite)) throw new Error('')
    this.suite = suite
    decorateCryptographicMaterial<WebCryptoDecryptionMaterial>(this)
    decorateDecryptionMaterial<WebCryptoDecryptionMaterial>(this)
    decorateWebCryptoMaterial<WebCryptoDecryptionMaterial>(this)
    this.setUnencryptedDataKey(unencryptedDataKey)
    Object.setPrototypeOf(this, WebCryptoDecryptionMaterial.prototype)
    Object.freeze(this)
  }
}
frozenClass(WebCryptoDecryptionMaterial)

export function isEncryptionMaterial(obj: any): obj is WebCryptoEncryptionMaterial|NodeEncryptionMaterial {
  return (obj instanceof WebCryptoEncryptionMaterial) || (obj instanceof NodeEncryptionMaterial)
}

export function isDecryptionMaterial(obj: any): obj is WebCryptoDecryptionMaterial|NodeDecryptionMaterial {
  return (obj instanceof WebCryptoDecryptionMaterial) || (obj instanceof NodeDecryptionMaterial)
}

export function decorateCryptographicMaterial<T extends CryptographicMaterial>(material: T) {
  let unencryptedDataKeyZeroed = false
  let unencryptedDataKey: Uint8Array|undefined

  const setUnencryptedDataKey = (dataKey: Uint8Array) => {
    /* Precondition: unencryptedDataKey must not be set.  Modifying the unencryptedDataKey is denied */
    if (unencryptedDataKey) throw new Error('')
    /* Precondition: dataKey must be Binary Data */
    if (!(dataKey instanceof Uint8Array)) throw new Error('')
    /* Precondition: The data key's length must agree with algorithm specification.
     * If this is not the case, it either means ciphertext was tampered
     * with or the keyring implementation is not setting the length properly.
     */
    if (dataKey.byteLength !== material.suite.keyLengthBytes) throw new Error('')
    unencryptedDataKey = dataKey
    return material
  }
  const getUnencryptedDataKey = (): Uint8Array => {
    /* Precondition: unencryptedDataKey must be set before we can return it. */
    if (!unencryptedDataKey) throw new Error('')
    /* Precondition: unencryptedDataKey must not be Zeroed out.
     * Returning a null key would be incredibly bad.
     */
    if (unencryptedDataKeyZeroed) throw new Error('')
    // inefficient, but immutable.  This makes it
    // impossible for someone to invalidate the 
    // unencryptedDataKey.  This protection seems
    // worth the inefficiency.
    return new Uint8Array(unencryptedDataKey)
  }
  Object.defineProperty(material, 'hasUnencryptedDataKey', {
    // Check that we have both not zeroed AND that we have not set
    get: () => !!unencryptedDataKey && !unencryptedDataKeyZeroed,
    enumerable: true,
  })
  const zeroUnencryptedDataKey = () => {
    /* Precondition: The unencryptedDataKey must be set to be zeroed. */
    if (!unencryptedDataKey) throw new Error('')
    unencryptedDataKey.fill(0)
    unencryptedDataKeyZeroed = true
    return material
  }
  Object.defineProperty(material, 'unencryptedDataKeyLength', {
    get: () => {
      /* Precondition: The unencryptedDataKey must be set to have a length. */
      if (!unencryptedDataKey) throw new Error('')
      /* Precondition: the unencryptedDataKey must not be Zeroed out.
       * returning information about the data key,
       * while not the worst thing may indicate misuse.
       * Checking the algorithm specification is the proper way
       * to do this
       */
      if (unencryptedDataKeyZeroed) throw new Error('')
      return unencryptedDataKey.byteLength
    },
    enumerable: true,
  })
  
  material.setUnencryptedDataKey = setUnencryptedDataKey
  material.getUnencryptedDataKey = getUnencryptedDataKey
  material.zeroUnencryptedDataKey = zeroUnencryptedDataKey

  return material
}

export function decorateEncryptionMaterial<T extends EncryptionMaterial>(material: T) {
  const encryptedDataKeys: EncryptedDataKey[] = []
  let signatureKey: Readonly<SignatureKey>|undefined

  const addEncryptedDataKey = (...ekds: EncryptedDataKey[]) => {
    /* Precondition: If a data key has not already been generated, there must be no EDKs.
     * Pushing EDKs on the list before the data key has been generated may cause the list of
     * EDKs to be inconsistent. (i.e., they would decrypt to different data keys.)
     */
    if (!material.hasUnencryptedDataKey) throw new Error('')
    /* Precondition: All eds's must be EncryptedDataKey
     * Putting things onto the list that are not EncryptedDataKey
     * may cause the list of EDKs to be inconsistent. (i.e. they may not serialize, or be mutable)
     */
    if (!ekds.every(edk => edk instanceof EncryptedDataKey)){
      throw new Error('Unsupported instance of encryptedDataKey')
    }
    encryptedDataKeys.push(...ekds)
    return material
  }

  readOnlyProperty<T, 'addEncryptedDataKey'>(material, 'addEncryptedDataKey', addEncryptedDataKey)
  Object.defineProperty(material, 'encryptedDataKeys', {
    // I only want EDKs added through addEncryptedDataKey
    // so I return a new array
    get: () => [...encryptedDataKeys],
    enumerable: true,
  })
  const setSignatureKey = (key: SignatureKey) => {
    /* Precondition: The SignatureKey stored must agree with the algorithm specification.
     * If this is not the case it means the MaterialManager or Keyring is not setting
     * the SignatureKey correctly
     */
    if (!material.suite.signatureCurve) throw new Error('')
    /* Precondition: signatureKey must not be set.  Modifying the signatureKey is denied. */
    if(signatureKey) throw new Error('')
    /* Precondition: key must be a SignatureKey. */
    if(!(key instanceof SignatureKey)) throw new Error('')
    signatureKey = key
    return material
  }
  readOnlyProperty<T, 'setSignatureKey'>(material, 'setSignatureKey', setSignatureKey)
  Object.defineProperty(material, 'signatureKey', {
    get: () => {
      /* Precondition: The SignatureKey requested must agree with the algorithm specification.
       * If this is not the case it means the MaterialManager or Keyring is not setting
       * the SignatureKey correctly
       */
      if (material.suite.signatureCurve && !signatureKey) throw new Error('')
      return signatureKey
    },
    enumerable: true,
  })

  return material
}

export function decorateDecryptionMaterial<T extends DecryptionMaterial>(material: T) {
  // Verification Key
  let verificationKey: Readonly<VerificationKey>|undefined
  const setVerificationKey = (key: VerificationKey) => {
    /* Precondition: The VerificationKey stored must agree with the algorithm specification.
     * If this is not the case it means the MaterialManager or Keyring is not setting
     * the VerificationKey correctly
     */
    if (!material.suite.signatureCurve) throw new Error('')
    /* Precondition: verificationKey must not be set.  Modifying the verificationKey is denied. */
    if(verificationKey) throw new Error('')
    /* Precondition: key must be a VerificationKey. */
    if(!(key instanceof VerificationKey)) throw new Error('')
    verificationKey = key
    return material
  }
  readOnlyProperty<T, 'setVerificationKey'>(material, 'setVerificationKey', setVerificationKey)
  Object.defineProperty(material, 'verificationKey', {
    get: () => {
      /* Precondition: The VerificationKey requested must agree with the algorithm specification.
       * If this is not the case it means the MaterialManager or Keyring is not setting
       * the VerificationKey correctly
       */
      if (material.suite.signatureCurve && !verificationKey) throw new Error('')
      return verificationKey
    },
    enumerable: true,
  })

  return material
}

export function decorateWebCryptoMaterial<T extends WebCryptoMaterial>(material: T) {
  let cryptoKey: Readonly<CryptoKey|MixedBackendCryptoKey>|undefined

  const setCryptoKey = (dataKey: CryptoKey|MixedBackendCryptoKey) => {
    /* Precondition: cryptoKey must not be set.  Modifying the cryptoKey is denied */
    if(cryptoKey) throw new Error('')
    /* Precondition: The CryptoKey must not be extractable.
     * It is expected that the unencryptedDataKey is how we are handling the
     * the data key.  If we zero out the unencryptedDataKey, the cryptoKey
     * should not be a vector to learn the unencryptedDataKey.
     */
    if (isCryptoKeyExtractable(<CryptoKey>dataKey)) throw new Error('')
    
    if ((<MixedBackendCryptoKey>dataKey).zeroByteCryptoKey && (<MixedBackendCryptoKey>dataKey).nonZeroByteCryptoKey) {
      const {zeroByteCryptoKey, nonZeroByteCryptoKey} = (<MixedBackendCryptoKey>dataKey)
      /* Precondition: The CryptoKey's inside MixedBackendCryptoKey must not be extractable.
       * It is expected that the unencryptedDataKey is how we are handling the
       * the data key.  If we zero out the unencryptedDataKey, the cryptoKey
       * should not be a vector to learn the unencryptedDataKey.
       */
      if (isCryptoKeyExtractable(zeroByteCryptoKey) || isCryptoKeyExtractable(nonZeroByteCryptoKey)) throw new Error('')
      cryptoKey = Object.freeze({zeroByteCryptoKey, nonZeroByteCryptoKey})
    } else if ((<CryptoKey>dataKey).algorithm) {
      cryptoKey = dataKey
    } else {
      throw new Error('')
    }

    return material
  }

  readOnlyProperty<T, 'setCryptoKey'>(material, 'setCryptoKey', setCryptoKey)
  Object.defineProperty(material, 'cryptoKey', {
    get: () => {
      /* Precondition: The cryptoKey must be set before we can return it. */
      if (!cryptoKey) throw new Error('')
      // In the case of MixedBackendCryptoKey the object
      // has already been frozen above so it is safe to return
      return cryptoKey
    },
    enumerable: true,
  })

  return material
}

function isCryptoKeyExtractable(dataKey: CryptoKey) {
  return dataKey.algorithm && dataKey.extractable
}