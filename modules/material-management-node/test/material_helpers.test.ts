// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  NodeDecryptionMaterial,
  NodeEncryptionMaterial,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  SignatureKey,
  VerificationKey,
  unwrapDataKey,
  needs,
} from '@aws-crypto/material-management'
import {
  nodeKdf,
  curryCryptoStream,
  getEncryptHelper,
  getDecryptionHelper,
} from '../src/material_helpers'
import {
  // @ts-ignore
  Decipheriv,
  // @ts-ignore
  Cipheriv,
  createECDH,
  createCipheriv,
  createDecipheriv,
} from 'crypto'

describe('nodeKdf', () => {
  it('Check for early return (Postcondition): No Node.js KDF, just return the unencrypted data key.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const test = unwrapDataKey(nodeKdf(material, new Uint8Array(5)).derivedKey)
    expect(test).to.deep.equal(dataKey)
  })

  it('Postcondition: Non-KDF algorithm suites *must* not have a commitment.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    expect(() =>
      nodeKdf(material, new Uint8Array(5), new Uint8Array(12))
    ).to.throw('Commitment not supported.')
  })

  it('HKDF SHA256', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const test = unwrapDataKey(nodeKdf(material, new Uint8Array(5)).derivedKey)
    expect(test).to.not.deep.equal(dataKey)
    expect(test.byteLength).to.equal(suite.keyLengthBytes)
  })

  it('HKDF SHA384', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const test = unwrapDataKey(nodeKdf(material, new Uint8Array(5)).derivedKey)
    expect(test).to.not.deep.equal(dataKey)
    expect(test.byteLength).to.equal(suite.keyLengthBytes)
  })

  it('HKDF 512', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)
    const { derivedKey, keyCommitment } = nodeKdf(material, new Uint8Array(32))
    const testKey = unwrapDataKey(derivedKey)
    expect(testKey).to.not.deep.equal(dataKey)
    expect(testKey.byteLength).to.equal(suite.keyLengthBytes)
    needs(keyCommitment, 'failure of nodeKdf')
    expect(keyCommitment.byteLength).to.equal(
      (suite.commitmentLength as number) / 8
    )
    expect(keyCommitment).to.deep.equal(
      Buffer.from('Ctu53IjHBCn5rUr4sfaOC8wqzDwxrKoMOJItVBX9+Xk=', 'base64')
    )
  })

  it('Precondition: Valid HKDF values must exist for Node.js.', () => {
    expect(() =>
      nodeKdf(
        {
          getUnencryptedDataKey() {},
          suite: {
            kdf: 'HKDF',
            kdfHash: 'sha256',
          } as any,
        } as any,
        {} as any
      )
    ).to.throw()

    expect(() =>
      nodeKdf(
        {
          getUnencryptedDataKey() {},
          suite: {
            kdf: 'NOT-HKDF',
            kdfHash: 'sha256',
          } as any,
        } as any,
        new Uint8Array(8)
      )
    ).to.throw()

    expect(() =>
      nodeKdf(
        {
          getUnencryptedDataKey() {},
          suite: {
            kdf: 'NOT-HKDF',
            kdfHash: 'NOT-sha256',
          } as any,
        } as any,
        new Uint8Array(8)
      )
    ).to.throw()
  })

  it('Postcondition: Non-committing Node algorithm suites *must* not have a commitment.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    expect(() =>
      nodeKdf(material, new Uint8Array(5), new Uint8Array(1))
    ).to.throw('Commitment not supported.')
  })
  it('Precondition: For committing algorithms, the nonce *must* be 256 bit.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)
    expect(() => nodeKdf(material, new Uint8Array(5))).to.throw(
      'Nonce is not the correct length for committed algorithm suite.'
    )
  })

  it('Precondition: If material is NodeDecryptionMaterial the key commitments *must* match.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
    )
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const encryptionMaterial = new NodeEncryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(dataKey), {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
    const decryptionMaterial = new NodeDecryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(dataKey), {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    })
    const nonce = new Uint8Array(32)
    const wrongKeyCommitment = new Uint8Array(32)

    expect(() =>
      nodeKdf(encryptionMaterial, nonce, wrongKeyCommitment)
    ).to.throw('Invalid arguments.')
    expect(() =>
      nodeKdf(decryptionMaterial, nonce, wrongKeyCommitment)
    ).to.throw('Commitment does not match.')
  })
})

describe('curryCryptoStream', () => {
  it('return a Cipheriv', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const { getCipher: test } = curryCryptoStream(
      material,
      createCipheriv
    )(new Uint8Array(16))
    const iv = new Uint8Array(12)
    const cipher = test(iv)
    expect(cipher).to.be.instanceOf(Cipheriv)
  })

  it('return a Decipheriv', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeDecryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const test = curryCryptoStream(
      material,
      createDecipheriv
    )(new Uint8Array(16))
    const iv = new Uint8Array(12)
    const decipher = test(iv)
    expect(decipher).to.be.instanceOf(Decipheriv)
  })

  it('Precondition: material must be either NodeEncryptionMaterial or NodeDecryptionMaterial.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => curryCryptoStream({ suite } as any, {} as any)).to.throw(
      'Unsupported cryptographic material.'
    )
  })

  it('Precondition: The length of the IV must match the NodeAlgorithmSuite specification.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const { getCipher: test } = curryCryptoStream(
      material,
      createCipheriv
    )(new Uint8Array(16))
    const iv = new Uint8Array(1)
    expect(() => test(iv)).to.throw()
  })

  it('Precondition: The material must have not been zeroed.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const { getCipher: test } = curryCryptoStream(
      material,
      createCipheriv
    )(new Uint8Array(16))
    material.zeroUnencryptedDataKey()
    const iv = new Uint8Array(12)
    expect(() => test(iv)).to.throw()
  })
})

describe('getEncryptHelper', () => {
  it('basic shape - uncommitted', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const helper = getEncryptHelper(material)
    expect(helper).to.haveOwnProperty('getCipherInfo').and.to.be.a('function')
    expect(helper).to.haveOwnProperty('getSigner').and.to.equal(undefined)
    expect(helper).to.haveOwnProperty('dispose').and.to.be.a('function')
    const { getCipher, keyCommitment } = helper.getCipherInfo(
      new Uint8Array(16)
    )
    expect(keyCommitment).to.equal(undefined)
    const iv = new Uint8Array(12)
    const cipher = getCipher(iv)
    expect(cipher).to.be.instanceOf(Cipheriv)

    helper.dispose()
    expect(material.hasUnencryptedDataKey).to.equal(false)
  })

  it('basic shape - committed', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const helper = getEncryptHelper(material)
    expect(helper).to.haveOwnProperty('getCipherInfo').and.to.be.a('function')
    expect(helper).to.haveOwnProperty('getSigner').and.to.equal(undefined)
    expect(helper).to.haveOwnProperty('dispose').and.to.be.a('function')
    const { getCipher, keyCommitment } = helper.getCipherInfo(
      new Uint8Array(32)
    )
    expect(keyCommitment)
      .lengthOf((suite.commitmentLength as number) / 8)
      .and.to.deep.equal(
        Buffer.from('Ctu53IjHBCn5rUr4sfaOC8wqzDwxrKoMOJItVBX9+Xk=', 'base64')
      )
    const iv = new Uint8Array(12)
    const cipher = getCipher(iv)
    expect(cipher).to.be.instanceOf(Cipheriv)

    helper.dispose()
    expect(material.hasUnencryptedDataKey).to.equal(false)
  })

  it('signer', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }

    const ecdh = createECDH(suite.signatureCurve || '')
    ecdh.generateKeys()
    const sigKey = new SignatureKey(
      ecdh.getPrivateKey(),
      ecdh.getPublicKey(),
      suite
    )

    material.setUnencryptedDataKey(dataKey, trace).setSignatureKey(sigKey)

    const helper = getEncryptHelper(material)
    if (typeof helper.getSigner !== 'function') throw new Error('bad')

    const { getCipher } = helper.getCipherInfo(new Uint8Array(16))
    const iv = new Uint8Array(12)
    const cipher = getCipher(iv)
    expect(cipher).to.be.instanceOf(Cipheriv)

    const signer = helper.getSigner()
    expect(signer).to.haveOwnProperty('awsCryptoSign').and.to.be.a('function')
    signer.update('data')
    const sig = signer.awsCryptoSign()
    expect(sig).instanceOf(Buffer)
  })

  it('Precondition: NodeEncryptionMaterial must have a valid data key.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeEncryptionMaterial(suite, {})

    expect(() => getEncryptHelper(material)).to.throw(
      'Material has no unencrypted data key.'
    )
  })

  it('Precondition: The NodeEncryptionMaterial must have not been zeroed.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    }

    const ecdh = createECDH(suite.signatureCurve || '')
    ecdh.generateKeys()
    const sigKey = new SignatureKey(
      ecdh.getPrivateKey(),
      ecdh.getPublicKey(),
      suite
    )

    material.setUnencryptedDataKey(dataKey, trace).setSignatureKey(sigKey)

    const helper = getEncryptHelper(material)
    material.zeroUnencryptedDataKey()

    expect(() => {
      if (!helper.getSigner) throw new Error('this should never happen')
      helper.getSigner()
    }).to.throw('Unencrypted data key has been zeroed.')
  })
})

describe('getDecryptionHelper', () => {
  it('first test - uncommitted', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeDecryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const helper = getDecryptionHelper(material)
    expect(helper).to.haveOwnProperty('getDecipherInfo').and.to.be.a('function')
    expect(helper).to.haveOwnProperty('getVerify').and.to.equal(undefined)
    expect(helper).to.haveOwnProperty('dispose').and.to.be.a('function')
    const getDecipher = helper.getDecipherInfo(new Uint8Array(16))
    const iv = new Uint8Array(12)
    const decipher = getDecipher(iv)
    expect(decipher).to.be.instanceOf(Decipheriv)

    helper.dispose()
    expect(material.hasUnencryptedDataKey).to.equal(false)
  })

  it('first test - committed', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    )
    const material = new NodeDecryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }
    material.setUnencryptedDataKey(new Uint8Array(dataKey), trace)

    const helper = getDecryptionHelper(material)
    expect(helper).to.haveOwnProperty('getDecipherInfo').and.to.be.a('function')
    expect(helper).to.haveOwnProperty('getVerify').and.to.be.a('function')
    expect(helper).to.haveOwnProperty('dispose').and.to.be.a('function')
    const getDecipher = helper.getDecipherInfo(
      new Uint8Array(32),
      Buffer.from('Ctu53IjHBCn5rUr4sfaOC8wqzDwxrKoMOJItVBX9+Xk=', 'base64')
    )
    const iv = new Uint8Array(12)
    const decipher = getDecipher(iv)
    expect(decipher).to.be.instanceOf(Decipheriv)

    helper.dispose()
    expect(material.hasUnencryptedDataKey).to.equal(false)
  })

  it('verify', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const material = new NodeDecryptionMaterial(suite, {})
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    }

    const ecdh = createECDH(suite.signatureCurve || '')
    ecdh.generateKeys()
    const verificationKey = new VerificationKey(ecdh.getPublicKey(), suite)

    material
      .setUnencryptedDataKey(dataKey, trace)
      .setVerificationKey(verificationKey)

    const helper = getDecryptionHelper(material)
    if (typeof helper.getVerify !== 'function') throw new Error('bad')

    const getDecipher = helper.getDecipherInfo(new Uint8Array(16))
    const iv = new Uint8Array(12)
    const decipher = getDecipher(iv)

    expect(decipher).to.be.instanceOf(Decipheriv)

    const verify = helper.getVerify()
    expect(verify).to.haveOwnProperty('awsCryptoVerify').and.to.be.a('function')
    verify.update('data')
    const isValid = verify.awsCryptoVerify(Buffer.alloc(5))
    expect(isValid).to.equal(false)
  })

  it('Precondition: NodeDecryptionMaterial must have a valid data key.', () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    const material = new NodeDecryptionMaterial(suite, {})
    expect(() => getDecryptionHelper(material)).to.throw(
      'Material has no unencrypted data key.'
    )
  })
})
