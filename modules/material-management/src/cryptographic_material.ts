// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  MixedBackendCryptoKey,
  SupportedAlgorithmSuites,
  AwsEsdkJsCryptoKey,
  AwsEsdkJsKeyUsage,
  EncryptionContext,
  AwsEsdkKeyObject,
  AwsEsdkCreateSecretKey,
} from './types'
import { EncryptedDataKey } from './encrypted_data_key'
import { SignatureKey, VerificationKey } from './signature_key'
import { frozenClass, readOnlyProperty } from './immutable_class'
import { KeyringTrace, KeyringTraceFlag } from './keyring_trace'
import { NodeAlgorithmSuite } from './node_algorithms'
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms'
import { needs } from './needs'

/* KeyObject were introduced in v11.
 * They protect the data key better than a Buffer.
 * Their use is preferred.
 * When they are available, the AWS Encryption SDK will proscribe their use.
 * See: https://nodejs.org/api/crypto.html#crypto_class_keyobject
 */
interface AwsEsdkKeyObjectInstanceOf {
  new (): AwsEsdkKeyObject
}
type AwsEsdkCrypto = {
  KeyObject: AwsEsdkKeyObjectInstanceOf
  createSecretKey: AwsEsdkCreateSecretKey
}
export const supportsKeyObject = (function () {
  try {
    const { KeyObject, createSecretKey } = require('crypto') as AwsEsdkCrypto // eslint-disable-line @typescript-eslint/no-var-requires
    if (!KeyObject || !createSecretKey) return false

    return { KeyObject, createSecretKey }
  } catch (ex) {
    return false
  }
})()

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
 * a Caching CMM exists it is important to ensure that the
 * unencrypted data key and its meta data can not be manipulated,
 * and that the unencrypted data key can be zeroed when
 * it is no longer needed.
 */

const timingSafeEqual: (a: Uint8Array, b: Uint8Array) => boolean =
  (function () {
    try {
      /* It is possible for `require` to return an empty object, or an object
       * that does not implement `timingSafeEqual`.
       * in this case I need a fallback
       */
      const { timingSafeEqual: nodeTimingSafeEqual } = require('crypto') // eslint-disable-line @typescript-eslint/no-var-requires
      return nodeTimingSafeEqual || portableTimingSafeEqual
    } catch (e) {
      return portableTimingSafeEqual
    }
    /* https://codahale.com/a-lesson-in-timing-attacks/ */
    function portableTimingSafeEqual(a: Uint8Array, b: Uint8Array) {
      /* It is *possible* that a runtime could optimize this constant time function.
       * Adding `eval` could prevent the optimization, but this is no guarantee.
       * The eval below is commented out
       * because if a browser is using a Content Security Policy with `'unsafe-eval'`
       * it would fail on this eval.
       * The value in attempting to ensure that this function is not optimized
       * is not worth the cost of making customers allow `'unsafe-eval'`.
       * If you want to copy this function for your own use,
       * please review the timing-attack link above.
       * Side channel attacks are pernicious and subtle.
       */
      // eval('') // eslint-disable-line no-eval
      /* Check for early return (Postcondition) UNTESTED: Size is well-know information
       * and does not leak information about contents.
       */
      if (a.byteLength !== b.byteLength) return false

      let diff = 0
      for (let i = 0; i < b.length; i++) {
        diff |= a[i] ^ b[i]
      }
      return diff === 0
    }
  })()

export interface FunctionalCryptographicMaterial {
  hasValidKey: () => boolean
}

export interface CryptographicMaterial<T extends CryptographicMaterial<T>> {
  suite: SupportedAlgorithmSuites
  setUnencryptedDataKey: (
    dataKey: Uint8Array | AwsEsdkKeyObject,
    trace: KeyringTrace
  ) => T
  getUnencryptedDataKey: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey: () => T
  hasUnencryptedDataKey: boolean
  keyringTrace: KeyringTrace[]
  encryptionContext: Readonly<EncryptionContext>
}

export interface EncryptionMaterial<T extends CryptographicMaterial<T>>
  extends CryptographicMaterial<T> {
  encryptedDataKeys: EncryptedDataKey[]
  addEncryptedDataKey: (edk: EncryptedDataKey, flags: KeyringTraceFlag) => T
  setSignatureKey: (key: SignatureKey) => T
  signatureKey?: SignatureKey
}

export interface DecryptionMaterial<T extends CryptographicMaterial<T>>
  extends CryptographicMaterial<T> {
  setVerificationKey: (key: VerificationKey) => T
  verificationKey?: VerificationKey
}

export interface WebCryptoMaterial<T extends CryptographicMaterial<T>>
  extends CryptographicMaterial<T> {
  setCryptoKey: (
    dataKey: AwsEsdkJsCryptoKey | MixedBackendCryptoKey,
    trace: KeyringTrace
  ) => T
  getCryptoKey: () => AwsEsdkJsCryptoKey | MixedBackendCryptoKey
  hasCryptoKey: boolean
  validUsages: ReadonlyArray<AwsEsdkJsKeyUsage>
}

export class NodeEncryptionMaterial
  implements
    Readonly<EncryptionMaterial<NodeEncryptionMaterial>>,
    FunctionalCryptographicMaterial
{
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (
    dataKey: Uint8Array | AwsEsdkKeyObject,
    trace: KeyringTrace
  ) => NodeEncryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey!: () => NodeEncryptionMaterial
  hasUnencryptedDataKey!: boolean
  keyringTrace: KeyringTrace[] = []
  encryptedDataKeys!: EncryptedDataKey[]
  addEncryptedDataKey!: (
    edk: EncryptedDataKey,
    flags: KeyringTraceFlag
  ) => NodeEncryptionMaterial
  setSignatureKey!: (key: SignatureKey) => NodeEncryptionMaterial
  signatureKey?: SignatureKey
  encryptionContext: Readonly<EncryptionContext>
  constructor(suite: NodeAlgorithmSuite, encryptionContext: EncryptionContext) {
    /* Precondition: NodeEncryptionMaterial suite must be NodeAlgorithmSuite. */
    needs(
      suite instanceof NodeAlgorithmSuite,
      'Suite must be a NodeAlgorithmSuite'
    )
    this.suite = suite
    /* Precondition: NodeEncryptionMaterial encryptionContext must be an object, even if it is empty. */
    needs(
      encryptionContext && typeof encryptionContext === 'object',
      'Encryption context must be set'
    )
    this.encryptionContext = Object.freeze({ ...encryptionContext })
    // EncryptionMaterial have generated a data key on setUnencryptedDataKey
    const setFlags = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    decorateCryptographicMaterial<NodeEncryptionMaterial>(this, setFlags)
    decorateEncryptionMaterial<NodeEncryptionMaterial>(this)
    Object.setPrototypeOf(this, NodeEncryptionMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey() {
    return this.hasUnencryptedDataKey
  }
}
frozenClass(NodeEncryptionMaterial)

export class NodeDecryptionMaterial
  implements
    Readonly<DecryptionMaterial<NodeDecryptionMaterial>>,
    FunctionalCryptographicMaterial
{
  suite: NodeAlgorithmSuite
  setUnencryptedDataKey!: (
    dataKey: Uint8Array | AwsEsdkKeyObject,
    trace: KeyringTrace
  ) => NodeDecryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey!: () => NodeDecryptionMaterial
  hasUnencryptedDataKey!: boolean
  keyringTrace: KeyringTrace[] = []
  setVerificationKey!: (key: VerificationKey) => NodeDecryptionMaterial
  verificationKey?: VerificationKey
  encryptionContext: Readonly<EncryptionContext>
  constructor(suite: NodeAlgorithmSuite, encryptionContext: EncryptionContext) {
    /* Precondition: NodeDecryptionMaterial suite must be NodeAlgorithmSuite. */
    needs(
      suite instanceof NodeAlgorithmSuite,
      'Suite must be a NodeAlgorithmSuite'
    )
    this.suite = suite
    /* Precondition: NodeDecryptionMaterial encryptionContext must be an object, even if it is empty. */
    needs(
      encryptionContext && typeof encryptionContext === 'object',
      'Encryption context must be set'
    )
    this.encryptionContext = Object.freeze({ ...encryptionContext })
    // DecryptionMaterial have decrypted a data key on setUnencryptedDataKey
    const setFlags = KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    decorateCryptographicMaterial<NodeDecryptionMaterial>(this, setFlags)
    decorateDecryptionMaterial<NodeDecryptionMaterial>(this)
    Object.setPrototypeOf(this, NodeDecryptionMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey() {
    return this.hasUnencryptedDataKey
  }
}
frozenClass(NodeDecryptionMaterial)

export class WebCryptoEncryptionMaterial
  implements
    Readonly<EncryptionMaterial<WebCryptoEncryptionMaterial>>,
    Readonly<WebCryptoMaterial<WebCryptoEncryptionMaterial>>,
    FunctionalCryptographicMaterial
{
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (
    dataKey: Uint8Array | AwsEsdkKeyObject,
    trace: KeyringTrace
  ) => WebCryptoEncryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey!: () => WebCryptoEncryptionMaterial
  hasUnencryptedDataKey!: boolean
  keyringTrace: KeyringTrace[] = []
  encryptedDataKeys!: EncryptedDataKey[]
  addEncryptedDataKey!: (
    edk: EncryptedDataKey,
    flags: KeyringTraceFlag
  ) => WebCryptoEncryptionMaterial
  setSignatureKey!: (key: SignatureKey) => WebCryptoEncryptionMaterial
  signatureKey?: SignatureKey
  setCryptoKey!: (
    dataKey: AwsEsdkJsCryptoKey | MixedBackendCryptoKey,
    trace: KeyringTrace
  ) => WebCryptoEncryptionMaterial
  getCryptoKey!: () => AwsEsdkJsCryptoKey | MixedBackendCryptoKey
  hasCryptoKey!: boolean
  validUsages: ReadonlyArray<AwsEsdkJsKeyUsage>
  encryptionContext: Readonly<EncryptionContext>
  constructor(
    suite: WebCryptoAlgorithmSuite,
    encryptionContext: EncryptionContext
  ) {
    /* Precondition: WebCryptoEncryptionMaterial suite must be WebCryptoAlgorithmSuite. */
    needs(
      suite instanceof WebCryptoAlgorithmSuite,
      'Suite must be a WebCryptoAlgorithmSuite'
    )
    this.suite = suite
    this.validUsages = Object.freeze([
      'deriveKey',
      'encrypt',
    ] as AwsEsdkJsKeyUsage[])
    /* Precondition: WebCryptoEncryptionMaterial encryptionContext must be an object, even if it is empty. */
    needs(
      encryptionContext && typeof encryptionContext === 'object',
      'Encryption context must be set'
    )
    this.encryptionContext = Object.freeze({ ...encryptionContext })
    // EncryptionMaterial have generated a data key on setUnencryptedDataKey
    const setFlag = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    decorateCryptographicMaterial<WebCryptoEncryptionMaterial>(this, setFlag)
    decorateEncryptionMaterial<WebCryptoEncryptionMaterial>(this)
    decorateWebCryptoMaterial<WebCryptoEncryptionMaterial>(this, setFlag)
    Object.setPrototypeOf(this, WebCryptoEncryptionMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey() {
    return this.hasUnencryptedDataKey && this.hasCryptoKey
  }
}
frozenClass(WebCryptoEncryptionMaterial)

export class WebCryptoDecryptionMaterial
  implements
    Readonly<DecryptionMaterial<WebCryptoDecryptionMaterial>>,
    Readonly<WebCryptoMaterial<WebCryptoDecryptionMaterial>>,
    FunctionalCryptographicMaterial
{
  suite: WebCryptoAlgorithmSuite
  setUnencryptedDataKey!: (
    dataKey: Uint8Array | AwsEsdkKeyObject,
    trace: KeyringTrace
  ) => WebCryptoDecryptionMaterial
  getUnencryptedDataKey!: () => Uint8Array | AwsEsdkKeyObject
  zeroUnencryptedDataKey!: () => WebCryptoDecryptionMaterial
  hasUnencryptedDataKey!: boolean
  keyringTrace: KeyringTrace[] = []
  setVerificationKey!: (key: VerificationKey) => WebCryptoDecryptionMaterial
  verificationKey?: VerificationKey
  setCryptoKey!: (
    dataKey: AwsEsdkJsCryptoKey | MixedBackendCryptoKey,
    trace: KeyringTrace
  ) => WebCryptoDecryptionMaterial
  getCryptoKey!: () => AwsEsdkJsCryptoKey | MixedBackendCryptoKey
  hasCryptoKey!: boolean
  validUsages: ReadonlyArray<AwsEsdkJsKeyUsage>
  encryptionContext: Readonly<EncryptionContext>
  constructor(
    suite: WebCryptoAlgorithmSuite,
    encryptionContext: EncryptionContext
  ) {
    /* Precondition: WebCryptoDecryptionMaterial suite must be WebCryptoAlgorithmSuite. */
    needs(
      suite instanceof WebCryptoAlgorithmSuite,
      'Suite must be a WebCryptoAlgorithmSuite'
    )
    this.suite = suite
    this.validUsages = Object.freeze([
      'deriveKey',
      'decrypt',
    ] as AwsEsdkJsKeyUsage[])
    /* Precondition: WebCryptoDecryptionMaterial encryptionContext must be an object, even if it is empty. */
    needs(
      encryptionContext && typeof encryptionContext === 'object',
      'Encryption context must be set'
    )
    this.encryptionContext = Object.freeze({ ...encryptionContext })
    // DecryptionMaterial have decrypted a data key on setUnencryptedDataKey
    const setFlag = KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    decorateCryptographicMaterial<WebCryptoDecryptionMaterial>(this, setFlag)
    decorateDecryptionMaterial<WebCryptoDecryptionMaterial>(this)
    decorateWebCryptoMaterial<WebCryptoDecryptionMaterial>(this, setFlag)
    Object.setPrototypeOf(this, WebCryptoDecryptionMaterial.prototype)
    Object.freeze(this)
  }
  hasValidKey() {
    return this.hasCryptoKey
  }
}
frozenClass(WebCryptoDecryptionMaterial)

export function isEncryptionMaterial(
  obj: any
): obj is WebCryptoEncryptionMaterial | NodeEncryptionMaterial {
  return (
    obj instanceof WebCryptoEncryptionMaterial ||
    obj instanceof NodeEncryptionMaterial
  )
}

export function isDecryptionMaterial(
  obj: any
): obj is WebCryptoDecryptionMaterial | NodeDecryptionMaterial {
  return (
    obj instanceof WebCryptoDecryptionMaterial ||
    obj instanceof NodeDecryptionMaterial
  )
}

export function decorateCryptographicMaterial<
  T extends CryptographicMaterial<T>
>(material: T, setFlag: KeyringTraceFlag) {
  /* Precondition: setFlag must be in the set of KeyringTraceFlag.SET_FLAGS. */
  needs(setFlag & KeyringTraceFlag.SET_FLAGS, 'Invalid setFlag')
  /* When a KeyringTraceFlag is passed to setUnencryptedDataKey,
   * it must be valid for the type of material.
   * It is invalid to claim that EncryptionMaterial were decrypted.
   */
  const deniedSetFlags =
    (KeyringTraceFlag.SET_FLAGS ^ setFlag) |
    (setFlag === KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
      ? KeyringTraceFlag.DECRYPT_FLAGS
      : setFlag === KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
      ? KeyringTraceFlag.ENCRYPT_FLAGS
      : 0)

  let unencryptedDataKeyZeroed = false
  let unencryptedDataKey: AwsEsdkKeyObject | Uint8Array
  // This copy of the unencryptedDataKey is stored to insure that the
  // unencrypted data key is *never* modified.  Since the
  // unencryptedDataKey is returned by reference, any change
  // to it would be propagated to any cached versions.
  let udkForVerification: Uint8Array

  const setUnencryptedDataKey = (
    dataKey: Uint8Array | AwsEsdkKeyObject,
    trace: KeyringTrace
  ) => {
    /* Avoid making unnecessary copies of the dataKey. */
    const tempUdk =
      dataKey instanceof Uint8Array ? dataKey : unwrapDataKey(dataKey)
    /* All security conditions are tested here and failures will throw. */
    verifyUnencryptedDataKeyForSet(tempUdk, trace)
    unencryptedDataKey = wrapWithKeyObjectIfSupported(dataKey)
    udkForVerification = new Uint8Array(tempUdk)
    material.keyringTrace.push(trace)

    return material
  }
  const getUnencryptedDataKey = (): Uint8Array | AwsEsdkKeyObject => {
    /* Precondition: unencryptedDataKey must be set before we can return it. */
    needs(unencryptedDataKey, 'unencryptedDataKey has not been set')
    /* Precondition: unencryptedDataKey must not be Zeroed out.
     * Returning a null key would be incredibly bad.
     */
    needs(!unencryptedDataKeyZeroed, 'unencryptedDataKey has been zeroed.')
    /* Precondition: The unencryptedDataKey must not have been modified.
     * If the unencryptedDataKey is a KeyObject,
     * then the security around modification is handled in C.
     * Do not duplicate the secret just to check...
     */
    needs(
      !(unencryptedDataKey instanceof Uint8Array) ||
        timingSafeEqual(udkForVerification, unwrapDataKey(unencryptedDataKey)),
      'unencryptedDataKey has been corrupted.'
    )
    return unencryptedDataKey
  }
  Object.defineProperty(material, 'hasUnencryptedDataKey', {
    // Check that we have both not zeroed AND that we have not set
    get: () => !!unencryptedDataKey && !unencryptedDataKeyZeroed,
    enumerable: true,
  })
  const zeroUnencryptedDataKey = () => {
    /* These checks are separated on purpose.  It should be impossible to have only one unset.
     * *But* if it was the case, I *must* make sure I zero out the set one, and not leave it up to GC.
     * If I only checked on say unencryptedDataKey, and udkForVerification was somehow set,
     * doing the simplest thing would be to set both to new Uint8Array.
     * Leaving udkForVerification to be garbage collected.
     * This level of insanity is due to the fact that we are dealing with the unencrypted data key.
     */
    let unsetCount = 0
    /* Precondition: If the unencryptedDataKey has not been set, it should not be settable later. */
    if (!unencryptedDataKey) {
      unencryptedDataKey = new Uint8Array()
      unsetCount += 1
    }
    /* Precondition: If the udkForVerification has not been set, it should not be settable later. */
    if (!udkForVerification) {
      udkForVerification = new Uint8Array()
      unsetCount += 1
    }
    /* The KeyObject manages its own ref counter.
     * Once there are no more users, it will clean the memory.
     */
    if (!(unencryptedDataKey instanceof Uint8Array)) {
      unencryptedDataKey = new Uint8Array()
    }
    unencryptedDataKey.fill(0)
    udkForVerification.fill(0)
    unencryptedDataKeyZeroed = true

    /* Postcondition UNTESTED: Both unencryptedDataKey and udkForVerification must be either set or unset.
     * If it is ever the case that only one was unset, then something is wrong in a profound way.
     * It is not clear how this could ever happen, unless someone is manipulating the OS...
     */
    needs(
      unsetCount === 0 || unsetCount === 2,
      'Either unencryptedDataKey or udkForVerification was not set.'
    )
    return material
  }

  readOnlyProperty(material, 'setUnencryptedDataKey', setUnencryptedDataKey)
  readOnlyProperty(material, 'getUnencryptedDataKey', getUnencryptedDataKey)
  readOnlyProperty(material, 'zeroUnencryptedDataKey', zeroUnencryptedDataKey)

  return material

  function verifyUnencryptedDataKeyForSet(
    dataKey: Uint8Array,
    trace: KeyringTrace
  ) {
    /* Precondition: unencryptedDataKey must not be set.  Modifying the unencryptedDataKey is denied */
    needs(!unencryptedDataKey, 'unencryptedDataKey has already been set')
    /* Precondition: dataKey must be Binary Data */
    needs(dataKey instanceof Uint8Array, 'dataKey must be a Uint8Array')
    /* Precondition: dataKey should have an ArrayBuffer that *only* stores the key.
     * This is a simple check to make sure that the key is not stored on
     * a large potentially shared ArrayBuffer.
     * If this was the case, it may be possible to find or manipulate.
     */
    needs(
      dataKey.byteOffset === 0,
      'Unencrypted Master Key must be an isolated buffer.'
    )
    /* Precondition: The data key length must agree with algorithm specification.
     * If this is not the case, it either means ciphertext was tampered
     * with or the keyring implementation is not setting the length properly.
     */
    needs(
      dataKey.byteLength === material.suite.keyLengthBytes,
      'Key length does not agree with the algorithm specification.'
    )

    /* Precondition: Trace must be set, and the flag must indicate that the data key was generated. */
    needs(
      trace && trace.keyName && trace.keyNamespace,
      'Malformed KeyringTrace'
    )
    /* Precondition: On set the required KeyringTraceFlag must be set. */
    needs(trace.flags & setFlag, 'Required KeyringTraceFlag not set')
    /* Precondition: Only valid flags are allowed.
     * An unencrypted data key can not be both generated and decrypted.
     */
    needs(!(trace.flags & deniedSetFlags), 'Invalid KeyringTraceFlags set.')
  }
}

export function decorateEncryptionMaterial<T extends EncryptionMaterial<T>>(
  material: T
) {
  const deniedEncryptFlags =
    KeyringTraceFlag.SET_FLAGS | KeyringTraceFlag.DECRYPT_FLAGS
  const encryptedDataKeys: EncryptedDataKey[] = []
  let signatureKey: Readonly<SignatureKey> | undefined

  const addEncryptedDataKey = (
    edk: EncryptedDataKey,
    flags: KeyringTraceFlag
  ) => {
    /* Precondition: If a data key has not already been generated, there must be no EDKs.
     * Pushing EDKs on the list before the data key has been generated may cause the list of
     * EDKs to be inconsistent. (i.e., they would decrypt to different data keys.)
     */
    needs(material.hasUnencryptedDataKey, 'Unencrypted data key not set.')
    /* Precondition: Edk must be EncryptedDataKey
     * Putting things onto the list that are not EncryptedDataKey
     * may cause the list of EDKs to be inconsistent. (i.e. they may not serialize, or be mutable)
     */
    needs(
      edk instanceof EncryptedDataKey,
      'Unsupported instance of encryptedDataKey'
    )

    /* Precondition: flags must indicate that the key was encrypted. */
    needs(
      flags & KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY,
      'Encrypted data key flag must be set.'
    )

    /* Precondition: flags must not include a setFlag or a decrypt flag.
     * The setFlag is reserved for setting the unencrypted data key
     * and must only occur once in the set of KeyringTrace flags.
     * The two setFlags in use are:
     * KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
     * KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
     *
     * KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX is reserved for the decrypt path
     */
    needs(!(flags & deniedEncryptFlags), 'Invalid flag for EncryptedDataKey.')
    material.keyringTrace.push({
      keyName: edk.providerInfo,
      keyNamespace: edk.providerId,
      flags,
    })

    encryptedDataKeys.push(edk)
    return material
  }

  readOnlyProperty(material, 'addEncryptedDataKey', addEncryptedDataKey)
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
    needs(
      material.suite.signatureCurve,
      'Algorithm specification does not support signatures.'
    )
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
      needs(
        !!material.suite.signatureCurve === !!signatureKey,
        'Algorithm specification not satisfied.'
      )
      return signatureKey
    },
    enumerable: true,
  })

  return material
}

export function decorateDecryptionMaterial<T extends DecryptionMaterial<T>>(
  material: T
) {
  // Verification Key
  let verificationKey: Readonly<VerificationKey> | undefined
  const setVerificationKey = (key: VerificationKey) => {
    /* Precondition: The VerificationKey stored must agree with the algorithm specification.
     * If this is not the case it means the MaterialManager or Keyring is not setting
     * the VerificationKey correctly
     */
    needs(
      material.suite.signatureCurve,
      'Algorithm specification does not support signatures.'
    )
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
      needs(
        !!material.suite.signatureCurve === !!verificationKey,
        'Algorithm specification not satisfied.'
      )
      return verificationKey
    },
    enumerable: true,
  })

  return material
}

export function decorateWebCryptoMaterial<T extends WebCryptoMaterial<T>>(
  material: T,
  setFlags: KeyringTraceFlag
) {
  let cryptoKey:
    | Readonly<AwsEsdkJsCryptoKey | MixedBackendCryptoKey>
    | undefined

  const setCryptoKey = (
    dataKey: AwsEsdkJsCryptoKey | MixedBackendCryptoKey,
    trace: KeyringTrace
  ) => {
    /* Precondition: cryptoKey must not be set.  Modifying the cryptoKey is denied */
    needs(!cryptoKey, 'cryptoKey is already set.')
    /* Precondition: dataKey must be a supported type. */
    needs(
      isCryptoKey(dataKey) || isMixedBackendCryptoKey(dataKey),
      'Unsupported dataKey type.'
    )
    /* Precondition: The CryptoKey must match the algorithm suite specification. */
    needs(
      isValidCryptoKey(dataKey, material),
      'CryptoKey settings not acceptable.'
    )

    /* If the material does not have an unencrypted data key,
     * then we are setting the crypto key here and need a keyring trace .
     */
    if (!material.hasUnencryptedDataKey) {
      /* Precondition: If the CryptoKey is the only version, the trace information must be set here. */
      needs(
        trace && trace.keyName && trace.keyNamespace,
        'Malformed KeyringTrace'
      )
      /* Precondition: On setting the CryptoKey the required KeyringTraceFlag must be set. */
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
    return cryptoKey as Readonly<AwsEsdkJsCryptoKey | MixedBackendCryptoKey>
  }
  readOnlyProperty(material, 'getCryptoKey', getCryptoKey)

  Object.defineProperty(material, 'hasCryptoKey', {
    get: () => !!cryptoKey,
    enumerable: true,
  })

  return material
}

export function isCryptoKey(dataKey: any): dataKey is AwsEsdkJsCryptoKey {
  return (
    dataKey &&
    'algorithm' in dataKey &&
    'type' in dataKey &&
    'usages' in dataKey &&
    'extractable' in dataKey
  )
}

export function isValidCryptoKey<T extends WebCryptoMaterial<T>>(
  dataKey: AwsEsdkJsCryptoKey | MixedBackendCryptoKey,
  material: T
): boolean {
  if (!isCryptoKey(dataKey)) {
    const { zeroByteCryptoKey, nonZeroByteCryptoKey } = dataKey
    return (
      isValidCryptoKey(zeroByteCryptoKey, material) &&
      isValidCryptoKey(nonZeroByteCryptoKey, material)
    )
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

  /* MSRCrypto, for legacy reasons,
   * normalizes the algorithm name
   * to lower case.
   * https://github.com/microsoft/MSR-JavaScript-Crypto/issues/1
   * For now, I'm going to upper case the name.
   */

  // Only symmetric algorithms
  return (
    type === 'secret' &&
    // Must match the suite
    ((kdf && name.toUpperCase() === kdf) ||
      (name.toUpperCase() === encryption && length === keyLength)) &&
    /* Only valid usage are: encrypt|decrypt|deriveKey
     * The complexity between deriveKey and suite.kdf should be handled in the Material class.
     */
    usages.some((u) => validUsages.includes(u)) &&
    // Since CryptoKey can not be zeroized, not extractable is the next best thing
    !extractable
  )
}

function isMixedBackendCryptoKey(
  dataKey: any
): dataKey is MixedBackendCryptoKey {
  const { zeroByteCryptoKey, nonZeroByteCryptoKey } = dataKey
  return isCryptoKey(zeroByteCryptoKey) && isCryptoKey(nonZeroByteCryptoKey)
}

export function keyUsageForMaterial<T extends WebCryptoMaterial<T>>(
  material: T
): AwsEsdkJsKeyUsage {
  const { suite } = material
  if (suite.kdf) return 'deriveKey'
  return subtleFunctionForMaterial(material)
}

export function subtleFunctionForMaterial<T extends WebCryptoMaterial<T>>(
  material: T
) {
  if (material instanceof WebCryptoEncryptionMaterial) return 'encrypt'
  if (material instanceof WebCryptoDecryptionMaterial) return 'decrypt'

  throw new Error('Unsupported material')
}

export function unwrapDataKey(
  dataKey: Uint8Array | AwsEsdkKeyObject
): Uint8Array {
  if (dataKey instanceof Uint8Array) return dataKey
  if (supportsKeyObject && dataKey instanceof supportsKeyObject.KeyObject)
    return dataKey.export()

  throw new Error('Unsupported dataKey type')
}

export function wrapWithKeyObjectIfSupported(
  dataKey: Uint8Array | AwsEsdkKeyObject
): Uint8Array | AwsEsdkKeyObject {
  if (supportsKeyObject) {
    if (dataKey instanceof Uint8Array) {
      const ko = supportsKeyObject.createSecretKey(dataKey)
      /* Postcondition: Zero the secret.  It is now inside the KeyObject. */
      dataKey.fill(0)
      return ko
    }
    if (dataKey instanceof supportsKeyObject.KeyObject) return dataKey
  } else if (dataKey instanceof Uint8Array) {
    return dataKey
  }
  throw new Error('Unsupported dataKey type')
}
