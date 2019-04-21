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

import { MixedBackendCryptoKey, SupportedAlgorithmSuites } from './types' // eslint-disable-line no-unused-vars
import { EncryptedDataKey } from './encrypted_data_key'
import { SignatureKey, VerificationKey } from './signature_key'
import { frozenClass, readOnlyProperty } from './immutable_class'
import { KeyringTrace, KeyringTraceFlag } from './keyring_trace' // eslint-disable-line no-unused-vars
import { NodeAlgorithmSuite } from './node_algorithms'
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms'
import { needs } from './needs'

let timingSafeEqual: (a: Uint8Array, b: Uint8Array) => boolean
try {
  /* It is possible for `require` to return an empty object, or an object
   * that does not implement `timingSafeEqual`.
   * in this case I need a fallback
   */
  const { timingSafeEqual: nodeTimingSafeEqual } = require('crypto')
  timingSafeEqual = nodeTimingSafeEqual || portableTimingSafeEqual
} catch {
  timingSafeEqual = portableTimingSafeEqual
}
/* https://codahale.com/a-lesson-in-timing-attacks/ */
function portableTimingSafeEqual (a: Uint8Array, b: Uint8Array) {
  /* Check for early return (Postcondition): Size is well-know information
   * and does not leak information about contents.
   */
  if (a.byteLength !== b.byteLength) return false

  let diff = 0
  for (let i = 0; i < b.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return (diff === 0)
}

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

export interface FunctionalCryptographicMaterial {
  hasValidKey: () => boolean
}

export interface CryptographicMaterial<T extends CryptographicMaterial<T>> {
  suite: SupportedAlgorithmSuites
  setUnencryptedDataKey: (dataKey: Uint8Array, trace: KeyringTrace) => T
  getUnencryptedDataKey: () => Uint8Array
  zeroUnencryptedDataKey: () => T
  hasUnencryptedDataKey: boolean
  unencryptedDataKeyLength: number
  keyringTrace: KeyringTrace[]
}

export interface EncryptionMaterial<T extends CryptographicMaterial<T>> extends CryptographicMaterial<T> {
  encryptedDataKeys: EncryptedDataKey[]
  addEncryptedDataKey: (edk: EncryptedDataKey, flags: KeyringTraceFlag) => T
  setSignatureKey: (key: SignatureKey) => T
  signatureKey?: SignatureKey
}

export interface DecryptionMaterial<T extends CryptographicMaterial<T>> extends CryptographicMaterial<T> {
  setVerificationKey: (key: VerificationKey) => T
  verificationKey?: VerificationKey
}

export interface WebCryptoMaterial<T extends CryptographicMaterial<T>> extends CryptographicMaterial<T> {
  setCryptoKey: (dataKey: CryptoKey|MixedBackendCryptoKey, trace: KeyringTrace) => T
  getCryptoKey: () => CryptoKey|MixedBackendCryptoKey
  hasCryptoKey: boolean
  validUsages: ReadonlyArray<KeyUsage>
}

export class NodeEncryptionMaterial implements
  Readonly<EncryptionMaterial<NodeEncryptionMaterial>>,
  FunctionalCryptographicMaterial {
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array, trace: KeyringTrace) => NodeEncryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => NodeEncryptionMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  encryptedDataKeys!: EncryptedDataKey[]
  addEncryptedDataKey!: (edk: EncryptedDataKey, flags: KeyringTraceFlag) => NodeEncryptionMaterial
  setSignatureKey!: (key: SignatureKey) => NodeEncryptionMaterial
  signatureKey?: SignatureKey
  constructor (suite: NodeAlgorithmSuite) {
    /* Precondition: NodeEncryptionMaterial suite must be NodeAlgorithmSuite. */
    needs(suite instanceof NodeAlgorithmSuite, 'Suite must be a NodeAlgorithmSuite')
    this.suite = suite
    // EncryptionMaterial have generated a data key on setUnencryptedDataKey
    const setFlags = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    decorateCryptographicMaterial<NodeEncryptionMaterial>(this, setFlags)
    decorateEncryptionMaterial<NodeEncryptionMaterial>(this)
    Object.setPrototypeOf(this, NodeEncryptionMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey () {
    return this.hasUnencryptedDataKey
  }
}
frozenClass(NodeEncryptionMaterial)

export class NodeDecryptionMaterial implements
  Readonly<DecryptionMaterial<NodeDecryptionMaterial>>,
  FunctionalCryptographicMaterial {
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array, trace: KeyringTrace) => NodeDecryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => NodeDecryptionMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  setVerificationKey!: (key: VerificationKey) => NodeDecryptionMaterial
  verificationKey?: VerificationKey
  constructor (suite: NodeAlgorithmSuite) {
    /* Precondition: NodeDecryptionMaterial suite must be NodeAlgorithmSuite. */
    needs(suite instanceof NodeAlgorithmSuite, 'Suite must be a NodeAlgorithmSuite')
    this.suite = suite
    // DecryptionMaterial have decrypted a data key on setUnencryptedDataKey
    const setFlags = KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    decorateCryptographicMaterial<NodeDecryptionMaterial>(this, setFlags)
    decorateDecryptionMaterial<NodeDecryptionMaterial>(this)
    Object.setPrototypeOf(this, NodeDecryptionMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey () {
    return this.hasUnencryptedDataKey
  }
}
frozenClass(NodeDecryptionMaterial)

export class WebCryptoEncryptionMaterial implements
  Readonly<EncryptionMaterial<WebCryptoEncryptionMaterial>>,
  Readonly<WebCryptoMaterial<WebCryptoEncryptionMaterial>>,
  FunctionalCryptographicMaterial {
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array, trace: KeyringTrace) => WebCryptoEncryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => WebCryptoEncryptionMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  encryptedDataKeys!: EncryptedDataKey[]
  addEncryptedDataKey!: (edk: EncryptedDataKey, flags: KeyringTraceFlag) => WebCryptoEncryptionMaterial
  setSignatureKey!: (key: SignatureKey) => WebCryptoEncryptionMaterial
  signatureKey?: SignatureKey
  setCryptoKey!: (dataKey: CryptoKey|MixedBackendCryptoKey, trace: KeyringTrace) => WebCryptoEncryptionMaterial
  getCryptoKey!: () => CryptoKey|MixedBackendCryptoKey
  hasCryptoKey!: boolean
  validUsages: ReadonlyArray<KeyUsage>
  constructor (suite: WebCryptoAlgorithmSuite) {
    /* Precondition: WebCryptoEncryptionMaterial suite must be WebCryptoAlgorithmSuite. */
    needs(suite instanceof WebCryptoAlgorithmSuite, 'Suite must be a WebCryptoAlgorithmSuite')
    this.suite = suite
    this.validUsages = Object.freeze(<KeyUsage[]>['deriveKey', 'encrypt'])
    // EncryptionMaterial have generated a data key on setUnencryptedDataKey
    const setFlag = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    decorateCryptographicMaterial<WebCryptoEncryptionMaterial>(this, setFlag)
    decorateEncryptionMaterial<WebCryptoEncryptionMaterial>(this)
    decorateWebCryptoMaterial<WebCryptoEncryptionMaterial>(this, setFlag)
    Object.setPrototypeOf(this, WebCryptoEncryptionMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey () {
    return this.hasUnencryptedDataKey && this.hasCryptoKey
  }
}
frozenClass(WebCryptoEncryptionMaterial)

export class WebCryptoDecryptionMaterial implements
  Readonly<DecryptionMaterial<WebCryptoDecryptionMaterial>>,
  Readonly<WebCryptoMaterial<WebCryptoDecryptionMaterial>>,
  FunctionalCryptographicMaterial {
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (dataKey: Uint8Array, trace: KeyringTrace) => WebCryptoDecryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array
  zeroUnencryptedDataKey!: () => WebCryptoDecryptionMaterial
  hasUnencryptedDataKey!: boolean
  unencryptedDataKeyLength!: number
  keyringTrace: KeyringTrace[] = []
  setVerificationKey!: (key: VerificationKey) => WebCryptoDecryptionMaterial
  verificationKey?: VerificationKey
  setCryptoKey!: (dataKey: CryptoKey|MixedBackendCryptoKey, trace: KeyringTrace) => WebCryptoDecryptionMaterial
  getCryptoKey!: () => CryptoKey|MixedBackendCryptoKey
  hasCryptoKey!: boolean
  validUsages: ReadonlyArray<KeyUsage>
  constructor (suite: WebCryptoAlgorithmSuite) {
    /* Precondition: WebCryptoDecryptionMaterial suite must be WebCryptoAlgorithmSuite. */
    needs(suite instanceof WebCryptoAlgorithmSuite, 'Suite must be a WebCryptoAlgorithmSuite')
    this.suite = suite
    this.validUsages = Object.freeze(<KeyUsage[]>['deriveKey', 'decrypt'])
    // DecryptionMaterial have decrypted a data key on setUnencryptedDataKey
    const setFlag = KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    decorateCryptographicMaterial<WebCryptoDecryptionMaterial>(this, setFlag)
    decorateDecryptionMaterial<WebCryptoDecryptionMaterial>(this)
    decorateWebCryptoMaterial<WebCryptoDecryptionMaterial>(this, setFlag)
    Object.setPrototypeOf(this, WebCryptoDecryptionMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey () {
    return this.hasCryptoKey
  }
}
frozenClass(WebCryptoDecryptionMaterial)

export function isEncryptionMaterial (obj: any): obj is WebCryptoEncryptionMaterial|NodeEncryptionMaterial {
  return (obj instanceof WebCryptoEncryptionMaterial) || (obj instanceof NodeEncryptionMaterial)
}

export function isDecryptionMaterial (obj: any): obj is WebCryptoDecryptionMaterial|NodeDecryptionMaterial {
  return (obj instanceof WebCryptoDecryptionMaterial) || (obj instanceof NodeDecryptionMaterial)
}

export function decorateCryptographicMaterial<T extends CryptographicMaterial<T>> (material: T, setFlags: KeyringTraceFlag) {
  let unencryptedDataKeyZeroed = false
  let unencryptedDataKey: Uint8Array
  // This copy of the unencryptedDataKey is stored to insure that the
  // unencrypted data key is *never* modified.  Since the
  // unencryptedDataKey is returned by reference, any change
  // to it would be propagated to any cached versions.
  let udkForVerification: Uint8Array

  const setUnencryptedDataKey = (dataKey: Uint8Array, trace: KeyringTrace) => {
    /* Precondition: unencryptedDataKey must not be set.  Modifying the unencryptedDataKey is denied */
    needs(!unencryptedDataKey, 'unencryptedDataKey has already been set')
    /* Precondition: dataKey must be Binary Data */
    needs(dataKey instanceof Uint8Array, 'dataKey must be a Uint8Array')
    /* Precondition: dataKey should have an ArrayBuffer that *only* stores the key.
     * This is a simple check to make sure that the key is not stored on
     * a large potentially shared ArrayBuffer.
     * If this was the case, it may be possible to find or manipulate.
     */
    needs(dataKey.byteOffset === 0, 'Unencrypted Master Key must be an isolated buffer.')
    /* Precondition: The data key length must agree with algorithm specification.
     * If this is not the case, it either means ciphertext was tampered
     * with or the keyring implementation is not setting the length properly.
     */
    needs(dataKey.byteLength === material.suite.keyLengthBytes, 'Key length does not agree with the algorithm specification.')

    /* Precondition: Trace must be set, and the flag must indicate that the data key was generated. */
    needs(trace && trace.keyName && trace.keyNamespace, 'Malformed KeyringTrace')
    /* Precondition: On set the required KeyringTraceFlag must be set. */
    needs(trace.flags & setFlags, 'Required KeyringTraceFlag not set')
    material.keyringTrace.push(trace)

    unencryptedDataKey = dataKey
    udkForVerification = new Uint8Array(dataKey)

    return material
  }
  const getUnencryptedDataKey = (): Uint8Array => {
    /* Precondition: unencryptedDataKey must be set before we can return it. */
    needs(unencryptedDataKey, 'unencryptedDataKey has not been set')
    /* Precondition: unencryptedDataKey must not be Zeroed out.
     * Returning a null key would be incredibly bad.
     */
    needs(!unencryptedDataKeyZeroed, 'unencryptedDataKey has been zeroed.')
    /* Precondition: The unencryptedDataKey must not have been modified. */
    needs(timingSafeEqual(udkForVerification, unencryptedDataKey), 'unencryptedDataKey has been corrupted.')
    return unencryptedDataKey
  }
  Object.defineProperty(material, 'hasUnencryptedDataKey', {
    // Check that we have both not zeroed AND that we have not set
    get: () => !!unencryptedDataKey && !unencryptedDataKeyZeroed,
    enumerable: true
  })
  const zeroUnencryptedDataKey = () => {
    /* Precondition: If the unencryptedDataKey has not been set, it should not be settable. */
    if (!unencryptedDataKey) {
      unencryptedDataKey = new Uint8Array()
      udkForVerification = new Uint8Array()
    }
    unencryptedDataKey.fill(0)
    udkForVerification.fill(0)
    unencryptedDataKeyZeroed = true
    return material
  }
  Object.defineProperty(material, 'unencryptedDataKeyLength', {
    get: () => {
      /* Precondition: The unencryptedDataKey must be set to have a length. */
      needs(unencryptedDataKey, 'unencryptedDataKey has not been set')
      /* Precondition: the unencryptedDataKey must not be Zeroed out.
       * returning information about the data key,
       * while not the worst thing may indicate misuse.
       * Checking the algorithm specification is the proper way
       * to do this
       */
      needs(!unencryptedDataKeyZeroed, 'unencryptedDataKey has been zeroed.')
      return unencryptedDataKey.byteLength
    },
    enumerable: true
  })

  readOnlyProperty(material, 'setUnencryptedDataKey', setUnencryptedDataKey)
  readOnlyProperty(material, 'getUnencryptedDataKey', getUnencryptedDataKey)
  readOnlyProperty(material, 'zeroUnencryptedDataKey', zeroUnencryptedDataKey)

  return material
}

export function decorateEncryptionMaterial<T extends EncryptionMaterial<T>> (material: T) {
  const encryptedDataKeys: EncryptedDataKey[] = []
  let signatureKey: Readonly<SignatureKey>|undefined

  const addEncryptedDataKey = (edk: EncryptedDataKey, flags: KeyringTraceFlag) => {
    /* Precondition: If a data key has not already been generated, there must be no EDKs.
     * Pushing EDKs on the list before the data key has been generated may cause the list of
     * EDKs to be inconsistent. (i.e., they would decrypt to different data keys.)
     */
    needs(material.hasUnencryptedDataKey, 'Unencrypted data key not set.')
    /* Precondition: Edk must be EncryptedDataKey
     * Putting things onto the list that are not EncryptedDataKey
     * may cause the list of EDKs to be inconsistent. (i.e. they may not serialize, or be mutable)
     */
    needs(edk instanceof EncryptedDataKey, 'Unsupported instance of encryptedDataKey')

    /* Precondition: flags must indicate that the key was encrypted. */
    needs(flags & KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY, 'Encrypted data key flag must be set.')
    /* When the unencrypted data key is first set, a given wrapping key may or may not also encrypt that key.
     * This means that the first EDK that is added may already have a trace.
     * The flags for the EDK and the existing trace should be merged iif this is the first EDK
     * and the only existing trace corresponds to this EDK.
     */
    if (firstEdkAndTraceMatch(encryptedDataKeys, material.keyringTrace, edk)) {
      material.keyringTrace[0].flags |= flags
    } else {
      material.keyringTrace.push({ keyName: edk.providerInfo, keyNamespace: edk.providerId, flags })
    }

    encryptedDataKeys.push(edk)
    return material
  }

  readOnlyProperty(material, 'addEncryptedDataKey', addEncryptedDataKey)
  Object.defineProperty(material, 'encryptedDataKeys', {
    // I only want EDKs added through addEncryptedDataKey
    // so I return a new array
    get: () => [...encryptedDataKeys],
    enumerable: true
  })
  const setSignatureKey = (key: SignatureKey) => {
    /* Precondition: The SignatureKey stored must agree with the algorithm specification.
     * If this is not the case it means the MaterialManager or Keyring is not setting
     * the SignatureKey correctly
     */
    needs(material.suite.signatureCurve, 'Algorithm specification does not support signatures.')
    /* Precondition: signatureKey must not be set.  Modifying the signatureKey is denied. */
    needs(!signatureKey, 'Signature key has already been set.')
    /* Precondition: key must be a SignatureKey. */
    needs(key instanceof SignatureKey, 'Unsupported instance of key')
    signatureKey = key
    return material
  }
  readOnlyProperty(material, 'setSignatureKey', setSignatureKey)
  Object.defineProperty(material, 'signatureKey', {
    get: () => {
      /* Precondition: The SignatureKey requested must agree with the algorithm specification.
       * If this is not the case it means the MaterialManager or Keyring is not setting
       * the SignatureKey correctly
       */
      needs(!!material.suite.signatureCurve === !!signatureKey, 'Algorithm specification not satisfied.')
      return signatureKey
    },
    enumerable: true
  })

  return material
}

/* Verify that the this is the first EDK and that it matches the 1 and only 1 trace. */
function firstEdkAndTraceMatch (edks: EncryptedDataKey[], traces: KeyringTrace[], edk: EncryptedDataKey) {
  return edks.length === 0 &&
  traces.length === 1 &&
  edk.providerId === traces[0].keyNamespace &&
  edk.providerInfo === traces[0].keyName
}

export function decorateDecryptionMaterial<T extends DecryptionMaterial<T>> (material: T) {
  // Verification Key
  let verificationKey: Readonly<VerificationKey>|undefined
  const setVerificationKey = (key: VerificationKey) => {
    /* Precondition: The VerificationKey stored must agree with the algorithm specification.
     * If this is not the case it means the MaterialManager or Keyring is not setting
     * the VerificationKey correctly
     */
    needs(material.suite.signatureCurve, 'Algorithm specification does not support signatures.')
    /* Precondition: verificationKey must not be set.  Modifying the verificationKey is denied. */
    needs(!verificationKey, 'Verification key has already been set.')
    /* Precondition: key must be a VerificationKey. */
    needs(key instanceof VerificationKey, 'Unsupported instance of key')
    verificationKey = key
    return material
  }
  readOnlyProperty(material, 'setVerificationKey', setVerificationKey)
  Object.defineProperty(material, 'verificationKey', {
    get: () => {
      /* Precondition: The VerificationKey requested must agree with the algorithm specification.
       * If this is not the case it means the MaterialManager or Keyring is not setting
       * the VerificationKey correctly
       */
      needs(!!material.suite.signatureCurve === !!verificationKey, 'Algorithm specification not satisfied.')
      return verificationKey
    },
    enumerable: true
  })

  return material
}

export function decorateWebCryptoMaterial<T extends WebCryptoMaterial<T>> (material: T, setFlags: KeyringTraceFlag) {
  let cryptoKey: Readonly<CryptoKey|MixedBackendCryptoKey>|undefined

  const setCryptoKey = (dataKey: CryptoKey|MixedBackendCryptoKey, trace: KeyringTrace) => {
    /* Precondition: cryptoKey must not be set.  Modifying the cryptoKey is denied */
    needs(!cryptoKey, 'cryptoKey is already set.')
    /* Precondition: dataKey must be a supported type. */
    needs(isCryptoKey(dataKey) || isMixedBackendCryptoKey(dataKey), 'Unsupported dataKey type.')
    /* Precondition: The CryptoKey must match the algorithm suite specification. */
    needs(isValidCryptoKey(dataKey, material), 'CryptoKey settings not acceptable.')

    /* If the material does not have an unencrypted data key,
     * then we are setting the crypto key here and need a keyring trace .
     */
    if (!material.hasUnencryptedDataKey) {
      /* Precondition: If the CryptoKey is the only version, the trace information must be set here. */
      needs(trace && trace.keyName && trace.keyNamespace, 'Malformed KeyringTrace')
      /* Precondition: On set the required KeyringTraceFlag must be set. */
      needs(trace.flags & setFlags, 'Required KeyringTraceFlag not set')
      /* If I a setting a cryptoKey without an unencrypted data key,
       * an unencrypted data should never be set.
       * The expectation is if you are setting the cryptoKey *first* then
       * the unencrypted data key has already been "handled".
       * This ensures that a cryptoKey and an unencrypted data key always match.
       */
      material.zeroUnencryptedDataKey()
      material.keyringTrace.push(trace)
    }

    if (isCryptoKey(dataKey)) {
      cryptoKey = dataKey
    } else {
      const { zeroByteCryptoKey, nonZeroByteCryptoKey } = dataKey
      cryptoKey = Object.freeze({ zeroByteCryptoKey, nonZeroByteCryptoKey })
    }

    return material
  }

  readOnlyProperty(material, 'setCryptoKey', setCryptoKey)
  const getCryptoKey = () => {
    /* Precondition: The cryptoKey must be set before we can return it. */
    needs(cryptoKey, 'Crypto key is not set.')
    // In the case of MixedBackendCryptoKey the object
    // has already been frozen above so it is safe to return
    return <Readonly<CryptoKey|MixedBackendCryptoKey>>cryptoKey
  }
  readOnlyProperty(material, 'getCryptoKey', getCryptoKey)

  Object.defineProperty(material, 'hasCryptoKey', {
    get: () => !!cryptoKey,
    enumerable: true
  })

  return material
}

export function isCryptoKey (dataKey: any): dataKey is CryptoKey {
  return dataKey &&
    'algorithm' in dataKey &&
    'type' in dataKey &&
    'algorithm' in dataKey &&
    'usages' in dataKey &&
    'extractable' in dataKey
}

export function isValidCryptoKey<T extends WebCryptoMaterial<T>> (
  dataKey: CryptoKey|MixedBackendCryptoKey,
  material: T
) : boolean {
  if (!isCryptoKey(dataKey)) {
    const { zeroByteCryptoKey, nonZeroByteCryptoKey } = dataKey
    return isValidCryptoKey(zeroByteCryptoKey, material) &&
      isValidCryptoKey(nonZeroByteCryptoKey, material)
  }

  const { suite, validUsages } = material
  const { encryption, keyLength, kdf } = suite

  /* See:
   * https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey
   * https://developer.mozilla.org/en-US/docs/Web/API/AesKeyGenParams
   */

  const { type, algorithm, usages, extractable } = dataKey
  // @ts-ignore length is an optional value...
  const { name, length } = algorithm

  // Only symmetric algorithms
  return type === 'secret' &&
    // Must match the suite
    ((kdf && name === kdf) ||
     (name === encryption && length === keyLength)) &&
    /* Only valid usage are: encrypt|decrypt|deriveKey
     * The complexity between deriveKey and suite.kdf should be handled in the Material class.
     */
    usages.some(u => validUsages.includes(u)) &&
    // Since CryptoKey can not be zeroized, not extractable is the next best thing
    !extractable
}

function isMixedBackendCryptoKey (dataKey: any): dataKey is MixedBackendCryptoKey {
  const { zeroByteCryptoKey, nonZeroByteCryptoKey } = dataKey
  return isCryptoKey(zeroByteCryptoKey) && isCryptoKey(nonZeroByteCryptoKey)
}

export function keyUsageForMaterial<T extends WebCryptoMaterial<T>> (material: T): KeyUsage {
  const { suite } = material
  if (suite.kdf) return 'deriveKey'
  return subtleFunctionForMaterial(material)
}

export function subtleFunctionForMaterial<T extends WebCryptoMaterial<T>> (material: T) {
  if (material instanceof WebCryptoEncryptionMaterial) return 'encrypt'
  if (material instanceof WebCryptoDecryptionMaterial) return 'decrypt'

  throw new Error('Unsupported material')
}
