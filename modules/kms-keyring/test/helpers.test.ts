// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  generateDataKey,
  encrypt,
  decrypt,
  kmsResponseToEncryptedDataKey,
} from '../src/helpers'
import { EncryptedDataKey } from '@aws-crypto/material-management'

describe('kmsResponseToEncryptedDataKey', () => {
  it('return an EncryptedDataKey', () => {
    const response = {
      KeyId: 'asdf',
      CiphertextBlob: new Uint8Array(5),
      $metadata: {} as any,
    }
    const test = kmsResponseToEncryptedDataKey(response)
    expect(test).instanceOf(EncryptedDataKey)
    expect(test.providerId).to.equal('aws-kms')
    expect(test.providerInfo).to.equal('asdf')
    expect(test.encryptedDataKey.byteLength).to.equal(5)
  })
})

describe('generateDataKey', () => {
  it('return', async () => {
    // the string Plaintext as bytes
    const key = [80, 108, 97, 105, 110, 116, 101, 120, 116]
    const Plaintext = new Uint8Array(key)
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const GrantTokens = ['grantToken']
    const NumberOfBytes = 128
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = (region: string) => {
      expect(region).to.equal('us-east-1')
      return { generateDataKey }
      async function generateDataKey(input: any) {
        expect(input.KeyId).to.equal(KeyId)
        expect(input.GrantTokens).to.equal(GrantTokens)
        expect(input.NumberOfBytes).to.equal(NumberOfBytes)
        expect(input.EncryptionContext).to.equal(EncryptionContext)
        return {
          Plaintext,
          KeyId: 'KeyId',
          CiphertextBlob: new Uint8Array([1, 2, 3, 4]),
        }
      }
    }

    const test = await generateDataKey(
      clientProvider,
      NumberOfBytes,
      KeyId,
      EncryptionContext,
      GrantTokens
    )
    if (!test) throw new Error('never')
    expect(test.Plaintext).to.deep.equal(new Uint8Array(key))
    expect(test.KeyId).to.equal('KeyId')
    expect(test.CiphertextBlob).to.deep.equal(new Uint8Array([1, 2, 3, 4]))
  })

  it('Check for early return (Postcondition): clientProvider did not return a client for generateDataKey.', async () => {
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const GrantTokens = ['grantToken']
    const NumberOfBytes = 128
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = () => {
      return false
    }

    const test = await generateDataKey(
      clientProvider,
      NumberOfBytes,
      KeyId,
      EncryptionContext,
      GrantTokens
    )
    expect(test).to.equal(false)
  })

  it('Postcondition: KMS must return serializable generate data key.', async () => {
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const GrantTokens = ['grantToken']
    const NumberOfBytes = 128
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = () => {
      return { generateDataKey }
      function generateDataKey() {
        return {}
      }
    }

    try {
      await generateDataKey(
        clientProvider,
        NumberOfBytes,
        KeyId,
        EncryptionContext,
        GrantTokens
      )
    } catch {
      return
    }
    throw new Error('never')
  })
})

describe('encrypt', () => {
  it('return', async () => {
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const GrantTokens = ['grantToken']
    const Plaintext = new Uint8Array(5)
    const EncryptionContext = { some: 'context' }
    const CiphertextBlob = new Uint8Array([1, 2, 3, 4])

    const clientProvider: any = (region: string) => {
      expect(region).to.equal('us-east-1')
      return { encrypt }
      function encrypt(input: any) {
        expect(input.KeyId).to.equal(KeyId)
        expect(input.GrantTokens).to.equal(GrantTokens)
        expect(input.Plaintext).to.equal(Plaintext)
        expect(input.EncryptionContext).to.equal(EncryptionContext)
        return {
          KeyId: 'KeyId',
          CiphertextBlob,
        }
      }
    }

    const test = await encrypt(
      clientProvider,
      Plaintext,
      KeyId,
      EncryptionContext,
      GrantTokens
    )
    if (!test) throw new Error('never')
    expect(test.KeyId).to.equal('KeyId')
    expect(test.CiphertextBlob).to.deep.equal(CiphertextBlob)
  })

  it('Check for early return (Postcondition): clientProvider did not return a client for encrypt.', async () => {
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const GrantTokens = ['grantToken']
    const Plaintext = new Uint8Array(5)
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = () => {
      return false
    }

    const test = await encrypt(
      clientProvider,
      Plaintext,
      KeyId,
      EncryptionContext,
      GrantTokens
    )
    expect(test).to.equal(false)
  })

  it('Postcondition: KMS must return serializable encrypted data key.', async () => {
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const GrantTokens = ['grantToken']
    const Plaintext = new Uint8Array(5)
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = () => {
      return { encrypt }
      function encrypt() {
        return {}
      }
    }

    try {
      await encrypt(
        clientProvider,
        Plaintext,
        KeyId,
        EncryptionContext,
        GrantTokens
      )
    } catch {
      return
    }
    throw new Error('never')
  })
})

describe('decrypt', () => {
  it('return', async () => {
    // the string Plaintext as bytes
    const key = [80, 108, 97, 105, 110, 116, 101, 120, 116]
    const Plaintext = new Uint8Array(key)
    const GrantTokens = ['grantToken']
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: KeyId,
      encryptedDataKey: new Uint8Array(5),
    })
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = (region: string) => {
      expect(region).to.equal('us-east-1')
      return { decrypt }
      function decrypt(input: any) {
        expect(input.KeyId).to.equal(KeyId)
        expect(input.GrantTokens).to.equal(GrantTokens)
        expect(input.CiphertextBlob).lengthOf(5)
        expect(input.EncryptionContext).to.equal(EncryptionContext)
        return {
          KeyId: 'KeyId',
          Plaintext,
        }
      }
    }

    const test = await decrypt(
      clientProvider,
      edk,
      EncryptionContext,
      GrantTokens
    )
    if (!test) throw new Error('never')
    expect(test.KeyId).to.equal('KeyId')
    expect(test.Plaintext).to.deep.equal(new Uint8Array(key))
  })

  it('Precondition:  The EDK must be a KMS edk.', async () => {
    const GrantTokens = ['grantToken']
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const edk = new EncryptedDataKey({
      providerId: 'NOTaws-kms',
      providerInfo: KeyId,
      encryptedDataKey: new Uint8Array(5),
    })
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = () => {
      return { decrypt }
      function decrypt() {
        return {
          KeyId: 'KeyId',
          Plaintext: 'Plaintext',
        }
      }
    }

    try {
      await decrypt(clientProvider, edk, EncryptionContext, GrantTokens)
    } catch {
      return
    }
    throw new Error('never')
  })

  it('Check for early return (Postcondition): clientProvider did not return a client for decrypt.', async () => {
    const GrantTokens = ['grantToken']
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: KeyId,
      encryptedDataKey: new Uint8Array(5),
    })
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = () => {
      return false
    }

    const test = await decrypt(
      clientProvider,
      edk,
      EncryptionContext,
      GrantTokens
    )
    expect(test).to.equal(false)
  })

  it('Postcondition: KMS must return usable decrypted key.', async () => {
    const GrantTokens = ['grantToken']
    const KeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: KeyId,
      encryptedDataKey: new Uint8Array(5),
    })
    const EncryptionContext = { some: 'context' }

    const clientProvider: any = () => {
      return { decrypt }
      function decrypt() {
        return {}
      }
    }

    try {
      await decrypt(clientProvider, edk, EncryptionContext, GrantTokens)
    } catch {
      return
    }
    throw new Error('never')
  })
})
