// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  AwsKmsMrkAwareSymmetricDiscoveryKeyringBrowser,
  AwsKmsMrkAwareSymmetricKeyringBrowser,
} from '../src/index'
import {
  KeyringWebCrypto,
  WebCryptoEncryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  WebCryptoDecryptionMaterial,
} from '@aws-crypto/material-management-browser'
import { KMS as V3KMS } from '@aws-sdk/client-kms'

chai.use(chaiAsPromised)
const { expect } = chai

describe('AwsKmsMrkAwareSymmetricDiscoveryKeyringBrowser::constructor', () => {
  it('constructor decorates', async () => {
    const discoveryFilter = { accountIDs: ['658956600833'], partition: 'aws' }
    const grantTokens = ['grant']
    const client: any = { config: { region: 'us-west-2' } }

    const test = new AwsKmsMrkAwareSymmetricDiscoveryKeyringBrowser({
      client,
      discoveryFilter,
      grantTokens,
    })

    expect(test.discoveryFilter).to.deep.equal(discoveryFilter)
    expect(test.client).to.equal(client)
    expect(test.grantTokens).to.equal(grantTokens)
  })

  it('instance of KeyringWebCrypto', () => {
    const discoveryFilter = { accountIDs: ['658956600833'], partition: 'aws' }
    const grantTokens = ['grant']
    const client: any = { config: { region: 'us-west-2' } }

    const test = new AwsKmsMrkAwareSymmetricDiscoveryKeyringBrowser({
      client,
      discoveryFilter,
      grantTokens,
    })

    expect(test instanceof KeyringWebCrypto).to.equal(true)
  })
})

/* Injected from @aws-sdk/karma-credential-loader. */
declare const credentials: any

describe('AwsKmsMrkAwareSymmetricKeyringBrowser can encrypt/decrypt with AWS SDK v3 client', () => {
  const discoveryFilter = { accountIDs: ['658956600833'], partition: 'aws' }

  const eastKeyId =
    'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
  const grantTokens = ['grant']
  const encryptionContext = { some: 'context' }
  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
  )

  const keyring = new AwsKmsMrkAwareSymmetricDiscoveryKeyringBrowser({
    // Note the difference in the region from the keyId
    client: new V3KMS({ region: 'us-west-2', credentials }),
    discoveryFilter,
    grantTokens,
  })

  it('throws an error on encrypt', async () => {
    const material = new WebCryptoEncryptionMaterial(suite, encryptionContext)
    return expect(keyring.onEncrypt(material)).to.rejectedWith(
      Error,
      'AwsKmsMrkAwareSymmetricDiscoveryKeyring cannot be used to encrypt'
    )
  })

  it('can decrypt an EncryptedDataKey', async () => {
    const encryptKeyring = new AwsKmsMrkAwareSymmetricKeyringBrowser({
      client: new V3KMS({ region: 'us-east-1', credentials }),
      keyId: eastKeyId,
      grantTokens,
    })
    const encryptMaterial = await encryptKeyring.onEncrypt(
      new WebCryptoEncryptionMaterial(suite, encryptionContext)
    )
    const [edk] = encryptMaterial.encryptedDataKeys

    const material = await keyring.onDecrypt(
      new WebCryptoDecryptionMaterial(suite, encryptionContext),
      [edk]
    )
    const test = await keyring.onDecrypt(material, [edk])
    expect(test.hasValidKey()).to.equal(true)
    // The UnencryptedDataKey should be zeroed, because the cryptoKey has been set
    expect(() => test.getUnencryptedDataKey()).to.throw()
  })
})
