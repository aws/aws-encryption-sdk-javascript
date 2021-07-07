// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  _importCryptoKey,
  importCryptoKey,
  WebCryptoKdf,
  deriveKeyCommitment,
  currySubtleFunction,
  getEncryptHelper,
  getDecryptionHelper,
  buildAlgorithmForKDF,
} from '../src/index'
import {
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  isValidCryptoKey,
  SignatureKey,
  VerificationKey,
  AwsEsdkJsCryptoKeyPair,
  AwsEsdkJsKeyUsage,
} from '@aws-crypto/material-management'
import {
  synchronousRandomValues,
  getWebCryptoBackend,
  getZeroByteSubtle,
  getNonZeroByteBackend,
} from '@aws-crypto/web-crypto-backend'

import { fromBase64 } from '@aws-sdk/util-base64-browser'

chai.use(chaiAsPromised)
const { expect } = chai

declare const CryptoKey: CryptoKey

describe('_importCryptoKey', () => {
  it('can import WebCryptoEncryptionMaterial with a algorithm suite without a KDF', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['encrypt'])

    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })

  it('can import WebCryptoEncryptionMaterial with a algorithm suite with a KDF', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })

  it('can import WebCryptoDecryptionMaterial with a algorithm suite without a KDF', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['decrypt'])
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })

  it('can import WebCryptoDecryptionMaterial with a algorithm suite with a KDF', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })
})

describe('importCryptoKey', () => {
  it('can import when backend is isFullSupportWebCryptoBackend', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()

    const cryptoKey = await importCryptoKey(backend, material, ['encrypt'])
    expect(cryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(cryptoKey, material)).to.equal(true)
  })

  it('can import when backend is mixed support', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const realBackend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(realBackend)
    /* Insuring that the backend support is mixed is complicated.
     * So I just make a mixed backend and pass that.
     */
    const mixedSupportBackend = {
      nonZeroByteSubtle: subtle,
      zeroByteSubtle: subtle,
    } as any

    const mixedBackendCryptoKey = await importCryptoKey(
      mixedSupportBackend,
      material,
      ['encrypt']
    )
    expect(mixedBackendCryptoKey).to.not.be.instanceOf(CryptoKey)
    const { nonZeroByteCryptoKey, zeroByteCryptoKey } =
      mixedBackendCryptoKey as any
    expect(nonZeroByteCryptoKey).to.be.instanceOf(CryptoKey)
    expect(zeroByteCryptoKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(nonZeroByteCryptoKey, material)).to.equal(true)
    expect(isValidCryptoKey(zeroByteCryptoKey, material)).to.equal(true)
  })
})

describe('deriveKeyCommitment', () => {
  it('can derive commitment', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    const keyCommitment = await deriveKeyCommitment(
      subtle,
      material,
      cryptoKey,
      new Uint8Array(32)
    )

    expect(keyCommitment).to.deep.equal(
      fromBase64('Ctu53IjHBCn5rUr4sfaOC8wqzDwxrKoMOJItVBX9+Xk=')
    )
  })

  it('can assert commitment', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const udk = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    const commitKey = fromBase64('Ctu53IjHBCn5rUr4sfaOC8wqzDwxrKoMOJItVBX9+Xk=')
    const keyCommitment = await deriveKeyCommitment(
      subtle,
      material,
      cryptoKey,
      new Uint8Array(32),
      commitKey
    )

    expect(keyCommitment).to.deep.equal(commitKey)
  })

  it('Check for early return (Postcondition): Algorithm suites without commitment do not have a commitment.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const udk = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    const keyCommitment = await deriveKeyCommitment(
      subtle,
      material,
      cryptoKey,
      new Uint8Array(32)
    )

    expect(keyCommitment).to.deep.equal(undefined)
  })

  it('Postcondition: Non-committing WebCrypto algorithm suites *must* not have a commitment.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const udk = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    const commitKey = fromBase64('Ctu53IjHBCn5rUr4sfaOC8wqzDwxrKoMOJItVBX9+Xk=')
    await expect(
      deriveKeyCommitment(
        subtle,
        material,
        cryptoKey,
        new Uint8Array(32),
        commitKey
      )
    ).to.rejectedWith(Error, 'Commitment not supported.')
  })

  it('Precondition: Commit key requires 256 bits of entropy.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    await expect(
      deriveKeyCommitment(subtle, material, cryptoKey, new Uint8Array(31))
    ).to.rejectedWith(
      Error,
      'Nonce is not the correct length for committed algorithm suite.'
    )
  })

  it('Precondition: If material is WebCryptoDecryptionMaterial the key commitments *must* match.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    )
    const udk = new Uint8Array(suite.keyLengthBytes).fill(1)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const commitKey = fromBase64('Ctu53IjHBCn5rUr4sfaOC8wqzDwxrKoMOJItVBX9+Xk=')

    const encryptionMaterial = new WebCryptoEncryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(udk, {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })

    const decryptionMaterial = new WebCryptoDecryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(udk, {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    })

    const decryptCryptoKey = await _importCryptoKey(
      subtle,
      decryptionMaterial,
      ['deriveKey']
    )

    const encryptCryptoKey = await _importCryptoKey(
      subtle,
      encryptionMaterial,
      ['deriveKey']
    )
    await expect(
      deriveKeyCommitment(
        subtle,
        encryptionMaterial,
        encryptCryptoKey,
        new Uint8Array(32),
        commitKey
      )
    ).to.rejectedWith(Error, 'Invalid arguments.')

    await expect(
      deriveKeyCommitment(
        subtle,
        decryptionMaterial,
        decryptCryptoKey,
        new Uint8Array(32),
        new Uint8Array(32)
      )
    ).to.rejectedWith(Error, 'Commitment does not match.')
  })
})

describe('buildAlgorithmForKDF', () => {
  it('basic non-committing suite', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    buildAlgorithmForKDF(suite, new Uint8Array(16))
  })

  it('basic committing suite', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
    )
    buildAlgorithmForKDF(suite, new Uint8Array(32))
  })

  it('Precondition: Valid HKDF values must exist for browsers.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const nonKdfSuite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    expect(() => buildAlgorithmForKDF(suite, undefined as any)).to.throw(
      'Invalid HKDF values.'
    )
    expect(() =>
      buildAlgorithmForKDF(nonKdfSuite, new Uint8Array(16))
    ).to.throw('Invalid HKDF values.')
  })

  it('Precondition: The message ID length must match the specification.', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )

    expect(() => buildAlgorithmForKDF(suite, new Uint8Array(15))).to.throw(
      'Message id length does not match specification.'
    )
  })

  it('Precondition: The message id length must match the algorithm suite.', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
    )

    expect(() => buildAlgorithmForKDF(suite, new Uint8Array(16))).to.throw(
      'Message id length does not match specification.'
    )
  })
})

describe('WebCryptoKdf', () => {
  it('returns a valid kdf key', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    const { deriveKey } = await WebCryptoKdf(
      subtle,
      material,
      cryptoKey,
      ['encrypt'],
      new Uint8Array(16)
    )
    expect(deriveKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(deriveKey, material)).to.equal(true)
    // for kdf...
    expect(deriveKey !== cryptoKey).to.equal(true)
  })

  it('Check for early return (Postcondition): No WebCrypto KDF, just return the unencrypted data key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const cryptoKey = await _importCryptoKey(subtle, material, ['encrypt'])
    const { deriveKey } = await WebCryptoKdf(
      subtle,
      material,
      cryptoKey,
      ['encrypt'],
      new Uint8Array(16)
    )
    expect(deriveKey).to.be.instanceOf(CryptoKey)
    expect(isValidCryptoKey(deriveKey, material)).to.equal(true)
    // for non-kdf...
    expect(deriveKey === cryptoKey).to.equal(true)
  })

  it('Postcondition: The derived key must conform to the algorith suite specification.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    const subtleHack = {
      deriveKey() {
        return {} as any
      },
    } as any

    const cryptoKey = await _importCryptoKey(subtle, material, ['deriveKey'])
    await expect(
      WebCryptoKdf(
        subtleHack,
        material,
        cryptoKey,
        ['encrypt'],
        new Uint8Array(16)
      )
    ).to.rejectedWith(Error)
  })
})

describe('currySubtleFunction', () => {
  it('can get encrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()

    const cryptoKey = await importCryptoKey(backend, material, ['encrypt'])
    material.setCryptoKey(cryptoKey, trace)

    const testInfo = currySubtleFunction(material, backend, 'encrypt')
    expect(testInfo).to.be.a('function')
    const { getSubtleEncrypt: testIvAad } = await testInfo(new Uint8Array(16))
    expect(testIvAad).to.be.a('function')
    const iv = new Uint8Array(suite.ivLength)
    const aad = new Uint8Array(1)
    const testFunction = testIvAad(iv, aad)
    expect(testFunction).to.be.a('function')
    const test = await testFunction(new Uint8Array(16))
    expect(test).to.be.instanceOf(ArrayBuffer)
  })

  it('Precondition: The material must have a CryptoKey.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()

    // 'Material must have a CryptoKey.'
    expect(() => currySubtleFunction(material, backend, 'encrypt')).to.throw()
  })

  it('Precondition: The cryptoKey and backend must match in terms of Mixed vs Full support.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    /* Insuring that the backend support is mixed is complicated.
     * So I just make a mixed backend and pass that.
     */
    const mixedSupportBackend = {
      nonZeroByteSubtle: subtle,
      zeroByteSubtle: subtle,
    } as any

    /* I always want the cryptoKey to not match the backend. */
    const cryptoKey = await _importCryptoKey(subtle, material, ['encrypt'])
    material.setCryptoKey(cryptoKey, trace)

    // 'CryptoKey vs WebCrypto backend mismatch.'
    expect(() =>
      currySubtleFunction(mixedSupportBackend, backend, 'encrypt')
    ).to.throw()
  })

  it('Precondition: The length of the IV must match the WebCryptoAlgorithmSuite specification.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)
    const backend = await getWebCryptoBackend()

    const cryptoKey = await importCryptoKey(backend, material, ['encrypt'])
    material.setCryptoKey(cryptoKey, trace)

    const testInfo = currySubtleFunction(material, backend, 'encrypt')
    expect(testInfo).to.be.a('function')
    const { getSubtleEncrypt: testIvAad } = await testInfo(new Uint8Array(16))
    expect(testIvAad).to.be.a('function')
    const iv = new Uint8Array(suite.ivLength - 1)
    const aad = new Uint8Array(1)
    expect(() => testIvAad(iv, aad)).to.throw()
  })

  it('can encrypt/decrypt 0 bytes', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)

    const backend = await getWebCryptoBackend()
    /* All of this _only_ matters in the case of a mixed backend.
     * So I force the issue.
     */
    const mixedBackend = {
      nonZeroByteSubtle: getZeroByteSubtle(backend),
      zeroByteSubtle: getNonZeroByteBackend(backend),
      randomValues: backend.randomValues,
    }

    const cryptoKey = await importCryptoKey(mixedBackend, material, [
      'encrypt',
      'decrypt',
    ])
    material.setCryptoKey(cryptoKey, trace)

    const iv = new Uint8Array(suite.ivLength)
    const aad = new Uint8Array(1)
    const tagLengthBytes = suite.tagLength / 8

    // Encrypt
    const testEncryptInfo = currySubtleFunction(
      material,
      mixedBackend,
      'encrypt'
    )
    const { getSubtleEncrypt: testEncryptIvAad } = await testEncryptInfo(
      new Uint8Array(1)
    )
    const testEncryptFunction = testEncryptIvAad(iv, aad)
    const testEncryptedData = await testEncryptFunction(new Uint8Array(0))
    // Because I encrypted 0 bytes, the data should _only_ be tagLength
    expect(testEncryptedData.byteLength).to.equal(tagLengthBytes)

    // Decrypt
    const testDecryptInfo = currySubtleFunction(
      material,
      mixedBackend,
      'decrypt'
    )
    const testDecryptIvAad = await testDecryptInfo(new Uint8Array(1))
    const testDecryptFunction = testDecryptIvAad(iv, aad)
    const testDecryptedData = await testDecryptFunction(
      new Uint8Array(testEncryptedData)
    )

    // Because I encrypted 0 bytes, the data should be 0 length
    expect(testDecryptedData.byteLength).to.equal(0)
  })

  it('Precondition: The WebCrypto AES-GCM decrypt API expects the data *and* tag together.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const trace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(udk, trace)

    const backend = await getWebCryptoBackend()
    /* All of this _only_ matters in the case of a mixed backend.
     * So I force the issue.
     */
    const mixedBackend = {
      nonZeroByteSubtle: getZeroByteSubtle(backend),
      zeroByteSubtle: getNonZeroByteBackend(backend),
      randomValues: backend.randomValues,
    }

    const cryptoKey = await importCryptoKey(mixedBackend, material, [
      'encrypt',
      'decrypt',
    ])
    material.setCryptoKey(cryptoKey, trace)

    const iv = new Uint8Array(suite.ivLength)
    const aad = new Uint8Array(1)
    const tagLengthBytes = suite.tagLength / 8

    // Encrypt
    const testEncryptInfo = currySubtleFunction(
      material,
      mixedBackend,
      'encrypt'
    )
    const { getSubtleEncrypt: testEncryptIvAad } = await testEncryptInfo(
      new Uint8Array(1)
    )
    const testEncryptFunction = testEncryptIvAad(iv, aad)
    const testEncryptedData = await testEncryptFunction(new Uint8Array(0))

    // Because I encrypted 0 bytes, the data should _only_ be tagLength
    expect(testEncryptedData.byteLength).to.equal(tagLengthBytes)

    // Decrypt
    const testDecryptInfo = currySubtleFunction(
      material,
      mixedBackend,
      'decrypt'
    )
    const testDecryptIvAad = await testDecryptInfo(new Uint8Array(1))
    const testDecryptFunction = testDecryptIvAad(iv, aad)

    for (let i = 0; tagLengthBytes > i; i++) {
      await expect(
        testDecryptFunction(new Uint8Array(testEncryptedData.slice(0, i)))
      ).to.eventually.rejectedWith(Error, 'Invalid data length.')
    }
  })

  it('no kdf, simple backend, can encrypt/decrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const encryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    const decryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    encryptionMaterial.setUnencryptedDataKey(udk, encryptTrace)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'encrypt',
      'decrypt',
    ])

    encryptionMaterial.setCryptoKey(cryptoKey, encryptTrace)
    decryptionMaterial.setCryptoKey(cryptoKey, decryptTrace)

    const info = synchronousRandomValues(16)
    const iv = synchronousRandomValues(suite.ivLength)
    const aad = synchronousRandomValues(5)
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const { getSubtleEncrypt } = await currySubtleFunction(
      encryptionMaterial,
      backend,
      'encrypt'
    )(info)
    const ciphertext = await getSubtleEncrypt(iv, aad)(data)

    const plaintext = await (
      await currySubtleFunction(decryptionMaterial, backend, 'decrypt')(info)
    )(
      iv,
      aad
    )(new Uint8Array(ciphertext))

    expect(new Uint8Array(plaintext)).to.deep.equal(data)
  })

  it('KDF, simple backend, can encrypt/decrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const encryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    const decryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    encryptionMaterial.setUnencryptedDataKey(udk, encryptTrace)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'deriveKey',
    ])

    encryptionMaterial.setCryptoKey(cryptoKey, encryptTrace)
    decryptionMaterial.setCryptoKey(cryptoKey, decryptTrace)

    const info = synchronousRandomValues(16)
    const iv = synchronousRandomValues(suite.ivLength)
    const aad = synchronousRandomValues(5)
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const ciphertext = await (
      await currySubtleFunction(encryptionMaterial, backend, 'encrypt')(info)
    ).getSubtleEncrypt(
      iv,
      aad
    )(data)
    const plaintext = await (
      await currySubtleFunction(decryptionMaterial, backend, 'decrypt')(info)
    )(
      iv,
      aad
    )(new Uint8Array(ciphertext))

    expect(new Uint8Array(plaintext)).to.deep.equal(data)
  })

  it('no kdf, mixed backend, can encrypt/decrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const encryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    const decryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    encryptionMaterial.setUnencryptedDataKey(udk, encryptTrace)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    /* Insuring that the backend support is mixed is complicated.
     * So I just make a mixed backend and pass that.
     */
    const mixedSupportBackend = {
      nonZeroByteSubtle: subtle,
      zeroByteSubtle: subtle,
    } as any

    const cryptoKey = await importCryptoKey(
      mixedSupportBackend,
      encryptionMaterial,
      ['encrypt', 'decrypt']
    )

    encryptionMaterial.setCryptoKey(cryptoKey, encryptTrace)
    decryptionMaterial.setCryptoKey(cryptoKey, decryptTrace)

    const messageId = synchronousRandomValues(16)
    const iv = synchronousRandomValues(suite.ivLength)
    const aad = synchronousRandomValues(5)
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const ciphertext = await (
      await currySubtleFunction(
        encryptionMaterial,
        mixedSupportBackend,
        'encrypt'
      )(messageId)
    ).getSubtleEncrypt(
      iv,
      aad
    )(data)
    const plaintext = await (
      await currySubtleFunction(
        decryptionMaterial,
        mixedSupportBackend,
        'decrypt'
      )(messageId)
    )(
      iv,
      aad
    )(new Uint8Array(ciphertext))

    expect(new Uint8Array(plaintext)).to.deep.equal(data)

    const ciphertextZeroByteData = await (
      await currySubtleFunction(
        encryptionMaterial,
        mixedSupportBackend,
        'encrypt'
      )(messageId)
    ).getSubtleEncrypt(
      iv,
      aad
    )(new Uint8Array(0))
    const plaintextZeroByteData = await (
      await currySubtleFunction(
        decryptionMaterial,
        mixedSupportBackend,
        'decrypt'
      )(messageId)
    )(
      iv,
      aad
    )(new Uint8Array(ciphertextZeroByteData))

    expect(new Uint8Array(plaintextZeroByteData)).to.deep.equal(
      new Uint8Array(0)
    )
  })

  it('kdf, mixed backend, can encrypt/decrypt', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const encryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    const decryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    encryptionMaterial.setUnencryptedDataKey(udk, encryptTrace)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)

    /* Insuring that the backend support is mixed is complicated.
     * So I just make a mixed backend and pass that.
     */
    const mixedSupportBackend = {
      nonZeroByteSubtle: subtle,
      zeroByteSubtle: subtle,
    } as any

    const cryptoKey = await importCryptoKey(
      mixedSupportBackend,
      encryptionMaterial,
      ['deriveKey']
    )

    encryptionMaterial.setCryptoKey(cryptoKey, encryptTrace)
    decryptionMaterial.setCryptoKey(cryptoKey, decryptTrace)

    const info = synchronousRandomValues(16)
    const iv = synchronousRandomValues(suite.ivLength)
    const aad = synchronousRandomValues(5)
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const ciphertext = await (
      await currySubtleFunction(
        encryptionMaterial,
        mixedSupportBackend,
        'encrypt'
      )(info)
    ).getSubtleEncrypt(
      iv,
      aad
    )(data)
    const plaintext = await (
      await currySubtleFunction(
        decryptionMaterial,
        mixedSupportBackend,
        'decrypt'
      )(info)
    )(
      iv,
      aad
    )(new Uint8Array(ciphertext))

    expect(new Uint8Array(plaintext)).to.deep.equal(data)

    const ciphertextZeroByteData = await (
      await currySubtleFunction(
        encryptionMaterial,
        mixedSupportBackend,
        'encrypt'
      )(info)
    ).getSubtleEncrypt(
      iv,
      aad
    )(new Uint8Array(0))
    const plaintextZeroByteData = await (
      await currySubtleFunction(
        decryptionMaterial,
        mixedSupportBackend,
        'decrypt'
      )(info)
    )(
      iv,
      aad
    )(new Uint8Array(ciphertextZeroByteData))

    expect(new Uint8Array(plaintextZeroByteData)).to.deep.equal(
      new Uint8Array(0)
    )
  })
})

// getEncryptHelper
// getDecryptionHelper

describe('getEncryptHelper/getDecryptionHelper', () => {
  it('encryption helpers without a signature', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const encryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    encryptionMaterial.setUnencryptedDataKey(udk, encryptTrace)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'deriveKey',
    ])
    encryptionMaterial.setCryptoKey(cryptoKey, encryptTrace)

    const test = await getEncryptHelper(encryptionMaterial)
    expect(test.getEncryptInfo).to.be.a('function')
    expect(test.subtleSign).to.equal(undefined)
    expect(test.dispose).to.be.a('function')
  })

  it('decryption helpers without a signature ', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const encryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    decryptionMaterial.setUnencryptedDataKey(udk, encryptTrace)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, decryptionMaterial, [
      'deriveKey',
    ])
    decryptionMaterial.setCryptoKey(cryptoKey, encryptTrace)

    const test = await getDecryptionHelper(decryptionMaterial)
    expect(test.getDecryptInfo).to.be.a('function')
    expect(test.subtleVerify).to.equal(undefined)
    expect(test.dispose).to.be.a('function')
  })

  it('encryption helpers with a signature', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const { signatureKey } = await sigKeys(suite)
    const encryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    encryptionMaterial
      .setUnencryptedDataKey(udk, encryptTrace)
      .setSignatureKey(signatureKey)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'deriveKey',
    ])
    encryptionMaterial.setCryptoKey(cryptoKey, encryptTrace)

    const test = await getEncryptHelper(encryptionMaterial)
    expect(test.getEncryptInfo).to.be.a('function')
    expect(test.subtleSign).to.be.a('function')
    expect(test.dispose).to.be.a('function')
  })

  it('decryption helpers with a signature ', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const { verificationKey } = await sigKeys(suite)
    const decryptionTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    decryptionMaterial
      .setUnencryptedDataKey(udk, decryptionTrace)
      .setVerificationKey(verificationKey)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, decryptionMaterial, [
      'deriveKey',
    ])
    decryptionMaterial.setCryptoKey(cryptoKey, decryptionTrace)

    const test = await getDecryptionHelper(decryptionMaterial)
    expect(test.getDecryptInfo).to.be.a('function')
    expect(test.subtleVerify).to.be.a('function')
    expect(test.dispose).to.be.a('function')
  })

  it('Precondition: WebCryptoEncryptionMaterial must have a valid data key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})

    await expect(getEncryptHelper(encryptionMaterial)).to.rejectedWith(Error)
  })

  it('Precondition: WebCryptoDecryptionMaterial must have a valid data key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})

    await expect(getDecryptionHelper(decryptionMaterial)).to.rejectedWith(Error)
  })

  it('can verify what was signed', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const decryptionMaterial = new WebCryptoDecryptionMaterial(suite, {})
    const encryptionMaterial = new WebCryptoEncryptionMaterial(suite, {})
    const udk = synchronousRandomValues(suite.keyLengthBytes)
    const { signatureKey, verificationKey } = await sigKeys(suite)
    const encryptTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    const decryptionTrace = {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    decryptionMaterial
      .setUnencryptedDataKey(udk, decryptionTrace)
      .setVerificationKey(verificationKey)
    encryptionMaterial
      .setUnencryptedDataKey(udk, encryptTrace)
      .setSignatureKey(signatureKey)

    const backend = await getWebCryptoBackend()
    const subtle = getZeroByteSubtle(backend)
    const cryptoKey = await _importCryptoKey(subtle, encryptionMaterial, [
      'deriveKey',
    ])

    encryptionMaterial.setCryptoKey(cryptoKey, encryptTrace)
    decryptionMaterial.setCryptoKey(cryptoKey, decryptionTrace)

    const { subtleSign } = await getEncryptHelper(encryptionMaterial)
    const { subtleVerify } = await getDecryptionHelper(decryptionMaterial)

    const data = new Uint8Array([1, 2, 3, 4, 5])
    // Make Typescript happy
    if (!subtleSign || !subtleVerify) throw new Error('never')

    const sig = await subtleSign(data)
    const test = await subtleVerify(new Uint8Array(sig), data)
    expect(test).to.equal(true)
  })
})

/* A simple helper to get signature/verification keys.
 * Basically a copy from the cmm.
 */
async function sigKeys(suite: WebCryptoAlgorithmSuite) {
  const { signatureCurve: namedCurve } = suite
  if (!namedCurve) throw new Error('never')
  const backend = await getWebCryptoBackend()
  const subtle = getZeroByteSubtle(backend)

  const webCryptoAlgorithm = { name: 'ECDSA', namedCurve }
  const extractable = false
  const usages = ['sign', 'verify'] as AwsEsdkJsKeyUsage[]
  const format = 'raw'

  const { publicKey, privateKey } = (await subtle.generateKey(
    webCryptoAlgorithm,
    extractable,
    usages
  )) as AwsEsdkJsCryptoKeyPair
  const publicKeyBytes = await subtle.exportKey(format, publicKey)
  const compressPoint = SignatureKey.encodeCompressPoint(
    new Uint8Array(publicKeyBytes),
    suite
  )

  const signatureKey = new SignatureKey(privateKey, compressPoint, suite)
  const verificationKey = new VerificationKey(publicKey, suite)

  return { signatureKey, verificationKey }
}
