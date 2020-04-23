// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { RawRsaKeyringNode, OaepHash } from '../src/index'
import {
  KeyringNode,
  NodeEncryptionMaterial,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  NodeDecryptionMaterial,
  unwrapDataKey,
} from '@aws-crypto/material-management-node'
import { oaepHashSupported } from '../src/oaep_hash_supported'

chai.use(chaiAsPromised)
const { expect } = chai

/* RSA Keys to test.
 * These keys are *Public*!
 * *DO NOT USE*
 *
 * to recrate
crypto.generateKeyPair('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
}, (e, p, v) => {
  public = p
  private = v
})
 */
const publicPem =
  '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu3eAVbBR//sN05yszjSh\n09D9L9e5q6W7z5SqdnsJ7WyENvDunOuuwIKBYOlj6P1XUKtxzwO4/v3Mu4SY4Tu2\n0rH3yP+rnGPSpRSwOOZOOBQcq6b1hK2ucGAbvYNZQSup/eqi1M+9hEgVBvMTrPfP\nm89N6xiwLaJhPAXLhVeAXroGv8yOIClkezcYkZxBx+/vdt0R31R8o08XoyniLWZt\np8xd2ge/hX8RxLc+7EhTouzHR/Pz63bhy9O9aNVVKcb2W5H4lOU9gNdPMEhmjERB\ne9M7u2rU2VyWSzwEpHx/8Vxl5T3f6i7lK0YLrFYhmmR311mCjZ50oEzJgsL+CtIO\nmq1aOYg1EJE7fOxzVPswG+BLp0r2Tx/4sevRh3Ap+BTSuOeTWlS1piV04JA5eeLE\nPrlScIVr4zj4uxMFkIxFMxMar4DD+TZGCnhqAokF56MZs9xndC6xWAnZWf3KV+il\nNN7yGo5CBGIv3Fu7CTsHTB7xOxAQyOeMSu0uGP2XO3N1DGRqv5imfRH8Jy5FhGzt\nwkSf8wPbUHINnqcQLnFvlqj1pc1j272tfVFDifr2IyToTyMIEY3S60VRBUs/F529\njCyhp8+0LMlw1WVbGt9Hxqwfzmt0rOfVc4/qnIKSc1IaBKCkwmeFOWK9qIGKMVtc\nMqsi59G6k0Ik3PjcwZ0gmv8CAwEAAQ==\n-----END PUBLIC KEY-----\n'
const privatePem =
  '-----BEGIN PRIVATE KEY-----\n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\nnUwWh19LU+597M0VXIKm2/H3v4up\n-----END PRIVATE KEY-----\n'

describe('RawRsaKeyringNode::constructor', () => {
  const keyName = 'keyName'
  const keyNamespace = 'keyNamespace'

  it('constructor decorates', async () => {
    const test = new RawRsaKeyringNode({
      rsaKey: {
        privateKey: privatePem,
        publicKey: publicPem,
      },
      keyName,
      keyNamespace,
    })

    expect(test.keyName).to.equal(keyName)
    expect(test.keyNamespace).to.equal(keyNamespace)
    expect(test._wrapKey).to.be.a('function')
    expect(test._unwrapKey).to.be.a('function')
    expect(test).to.be.instanceOf(KeyringNode)
  })

  it('can construct with only public key', () => {
    const testPublicOnly = new RawRsaKeyringNode({
      rsaKey: {
        publicKey: publicPem,
      },
      keyName,
      keyNamespace,
    })
    expect(testPublicOnly).to.be.instanceOf(RawRsaKeyringNode)
  })

  it('can construct with only private key', () => {
    const testPrivateOnly = new RawRsaKeyringNode({
      rsaKey: {
        privateKey: privatePem,
      },
      keyName,
      keyNamespace,
    })
    expect(testPrivateOnly).to.be.instanceOf(RawRsaKeyringNode)
  })

  it('Precondition: RsaKeyringNode needs either a public or a private key to operate.', () => {
    expect(
      () =>
        new RawRsaKeyringNode({
          keyName,
          keyNamespace,
          rsaKey: {},
        })
    ).to.throw()
  })

  it('Precondition: The AWS ESDK only supports specific hash values for OAEP padding.', () => {
    expect(
      () =>
        new RawRsaKeyringNode({
          keyName,
          keyNamespace,
          // @ts-ignore Valid hash, but not supported by the ESDK
          oaepHash: 'rmd160',
          rsaKey: { privateKey: privatePem },
        })
    ).to.throw('Unsupported oaepHash')
  })

  it('Precondition: RsaKeyringNode needs identifying information for encrypt and decrypt.', () => {
    expect(
      () =>
        new RawRsaKeyringNode({
          rsaKey: { privateKey: privatePem, publicKey: publicPem },
        } as any)
    ).to.throw()
    expect(
      () =>
        new RawRsaKeyringNode({
          rsaKey: { privateKey: privatePem, publicKey: publicPem },
          keyNamespace,
        } as any)
    ).to.throw()
    expect(
      () =>
        new RawRsaKeyringNode({
          rsaKey: { privateKey: privatePem, publicKey: publicPem },
          keyName,
        } as any)
    ).to.throw()
  })
})

const oaepHashOptions: OaepHash[] = [
  undefined,
  'sha1',
  'sha256',
  'sha384',
  'sha512',
]
oaepHashOptions
  .filter(
    (oaepHash) => oaepHashSupported || [undefined, 'sha1'].includes(oaepHash)
  )
  .forEach((oaepHash) =>
    describe(`RawRsaKeyringNode encrypt/decrypt for oaepHash=${
      oaepHash || 'undefined'
    }`, () => {
      const keyNamespace = 'keyNamespace'
      const keyName = 'keyName'
      const keyring = new RawRsaKeyringNode({
        rsaKey: { privateKey: privatePem, publicKey: publicPem },
        keyName,
        keyNamespace,
        oaepHash,
      })
      let encryptedDataKey: EncryptedDataKey

      it('can encrypt and create unencrypted data key', async () => {
        const suite = new NodeAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
        )
        const material = new NodeEncryptionMaterial(suite, {})
        const test = await keyring.onEncrypt(material)
        expect(test.hasValidKey()).to.equal(true)
        const udk = unwrapDataKey(test.getUnencryptedDataKey())
        expect(udk).to.have.lengthOf(suite.keyLengthBytes)
        expect(test.encryptedDataKeys).to.have.lengthOf(1)
        const [edk] = test.encryptedDataKeys
        expect(edk.providerId).to.equal(keyNamespace)
        encryptedDataKey = edk
      })

      it('can decrypt an EncryptedDataKey', async () => {
        const suite = new NodeAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
        )
        const material = new NodeDecryptionMaterial(suite, {})
        const test = await keyring.onDecrypt(material, [encryptedDataKey])
        expect(test.hasValidKey()).to.equal(true)
      })

      it('Precondition: Public key must be defined to support encrypt.', async () => {
        const keyring = new RawRsaKeyringNode({
          rsaKey: { privateKey: privatePem },
          keyName,
          keyNamespace,
        })

        const suite = new NodeAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
        )
        const material = new NodeEncryptionMaterial(suite, {})
        return expect(keyring.onEncrypt(material)).to.rejectedWith(Error)
      })

      it('Precondition: Private key must be defined to support decrypt.', async () => {
        const keyring = new RawRsaKeyringNode({
          rsaKey: { publicKey: publicPem },
          keyName,
          keyNamespace,
        })

        const suite = new NodeAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
        )
        const material = new NodeDecryptionMaterial(suite, {})
        return expect(
          keyring._unwrapKey(material, encryptedDataKey)
        ).to.rejectedWith(Error)
      })
    })
  )
