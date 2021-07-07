// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
// @ts-ignore
import chaiAsPromised from 'chai-as-promised'
import { buildDecrypt } from '../src/index'
import { _decrypt } from '../src/decrypt'
import {
  AlgorithmSuiteIdentifier,
  importForWebCryptoDecryptionMaterial,
  KeyringTraceFlag,
  KeyringWebCrypto,
  WebCryptoDecryptionMaterial,
  WebCryptoEncryptionMaterial,
} from '@aws-crypto/material-management-browser'
import * as fixtures from './fixtures'
import {
  CommitmentPolicy,
  MessageFormat,
  WebCryptoAlgorithmSuite,
} from '@aws-crypto/material-management'
import { fromBase64 } from '@aws-sdk/util-base64-browser'
chai.use(chaiAsPromised)
const { expect } = chai
const { decrypt } = buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

describe('decrypt', () => {
  it('buffer', async () => {
    const { plaintext: test, messageHeader } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.ciphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384()
    )

    expect(messageHeader.suiteId).to.equal(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )
    expect(messageHeader.encryptionContext).to.deep.equal(
      fixtures.encryptionContext()
    )
    expect(test).to.deep.equal(fixtures.plaintext())
  })

  it('Precondition: _decrypt needs a valid commitmentPolicy.', async () => {
    await expect(
      _decrypt(
        { commitmentPolicy: 'fake_policy' as any, maxEncryptedDataKeys: false },
        {} as any,
        {} as any
      )
    ).to.rejectedWith(Error, 'Invalid commitment policy.')
  })

  it('Precondition: _decrypt needs a valid maxEncryptedDataKeys.', async () => {
    await expect(
      _decrypt(
        {
          commitmentPolicy: CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
          maxEncryptedDataKeys: 0,
        },
        {} as any,
        {} as any
      )
    ).to.rejectedWith(Error, 'Invalid maxEncryptedDataKeys value.')
  })

  it('Precondition: The parsed header algorithmSuite in _decrypt must be supported by the commitmentPolicy.', async () => {
    await expect(
      _decrypt(
        {
          commitmentPolicy: CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
          maxEncryptedDataKeys: false,
        },
        fixtures.decryptKeyring(),
        fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384With4Frames()
      )
    ).to.rejectedWith(
      Error,
      'Configuration conflict. Cannot process message with ID'
    )
  })

  it('Precondition: The material algorithmSuite returned to _decrypt must be supported by the commitmentPolicy.', async () => {
    const cmm = {
      async decryptMaterials() {
        return new WebCryptoDecryptionMaterial(
          new WebCryptoAlgorithmSuite(
            AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
          ),
          {}
        )
      },
    } as any
    await expect(
      _decrypt(
        {
          commitmentPolicy: CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
          maxEncryptedDataKeys: false,
        },
        cmm,
        fromBase64(fixtures.compatibilityVectors().tests[0].ciphertext)
      )
    ).to.rejectedWith(
      Error,
      'Configuration conflict. Cannot process message with ID'
    )
  })

  it('Precondition: The sequenceNumber is required to monotonically increase, starting from 1.', async () => {
    return decrypt(
      fixtures.decryptKeyring(),
      fixtures.frameSequenceOutOfOrder()
    ).then(
      () => {
        throw new Error('should not succeed')
      },
      (err) => {
        expect(err).to.be.instanceOf(Error)
      }
    )
  })

  it('Postcondition: subtleVerify must validate the signature.', async () => {
    return decrypt(
      fixtures.decryptKeyring(),
      fixtures.invalidSignatureCiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384()
    ).then(
      () => {
        throw new Error('should not succeed')
      },
      (err) => {
        expect(err).to.be.instanceOf(Error)
        expect(err.message).to.equal('Invalid Signature')
      }
    )
  })

  it('verify incomplete chipertext will fail for an un-signed algorithm suite', async () => {
    const data = fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfWith4Frames()
    const keyring = fixtures.decryptKeyring()

    // First we make sure that the test vector is well formed
    await decrypt(keyring, data)

    // This is the real test:
    // trying to decrypt
    // on EVERY boundary
    for (let i = 0; data.byteLength > i; i++) {
      await expect(decrypt(keyring, data.slice(0, i))).to.rejectedWith(Error)
    }
  })

  it('verify incomplete chipertext will fail for a signed algorithm suite', async () => {
    const data =
      fixtures.base64CiphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384With4Frames()
    const keyring = fixtures.decryptKeyring()

    // First we make sure that the test vector is well formed
    await decrypt(keyring, data)

    // This is the real test:
    // trying to decrypt
    // on EVERY boundary
    for (let i = 0; data.byteLength > i; i++) {
      await expect(decrypt(keyring, data.slice(0, i))).to.rejectedWith(Error)
    }
  })

  it('can decrypt data with less than maxEncryptedDataKeys', async () => {
    const { decrypt } = buildDecrypt({
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      maxEncryptedDataKeys: 3,
    })
    const { plaintext } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.twoEdksMessage()
    )
    expect(plaintext).to.deep.equal(Buffer.from('asdf'))
  })

  it('can decrypt data with exactly maxEncryptedDataKeys', async () => {
    const { decrypt } = buildDecrypt({
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      maxEncryptedDataKeys: 3,
    })
    const { plaintext } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.threeEdksMessage()
    )
    expect(plaintext).to.deep.equal(Buffer.from('asdf'))
  })

  it('will not decrypt data with more than maxEncryptedDataKeys', async () => {
    const { decrypt } = buildDecrypt({
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      maxEncryptedDataKeys: 3,
    })
    await expect(
      decrypt(fixtures.decryptKeyring(), fixtures.fourEdksMessage())
    ).to.rejectedWith(Error, 'maxEncryptedDataKeys exceeded.')
  })
})

// prettier-ignore
const testVector = new Uint8Array([
  2,4,120,77,251,209,49,77,157,85,
  146,91,129,114,50,197,227,109,
  110,62,94,35,15,1,137,48,226,
  194,193,242,67,246,125,193,121,
  0,0,0,1,0,12,80,114,111,118,105,
  100,101,114,78,97,109,101,0,25,75,
  101,121,73,100,0,0,0,128,0,0,0,
  12,248,230,199,55,112,59,201,103,
  176,248,63,123,0,48,161,59,119,252,
  60,206,36,45,216,45,42,30,204,181,
  66,237,132,218,175,118,120,129,
  132,254,66,231,23,246,52,211,113,
  202,189,60,113,239,27,246,102,255,
  55,98,227,157,192,115,11,229,2,
  0,0,16,0,23,207,8,247,51,219,81,
  4,159,58,92,203,94,255,174,33,141,
  190,155,241,58,143,99,204,177,184,
  30,29,81,255,47,76,11,169,9,88,
  251,144,139,211,61,241,156,211,140,33,150,158,
  255,255,255,255,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,
  14,73,144,74,28,116,105,79,5,206,
  21,52,21,25,170,87,94,62,66,193,112,
  76,162,224,65,218,231,26,32,149,102])

describe('committing algorithm test', () => {
  // prettier-ignore
  const dataKey = new Uint8Array([
    250, 158, 190, 194,  19, 213, 195,
    217,  14, 173, 130, 217,  20, 196,
     65,  39, 105, 250,  86,  88, 186,
     79, 254, 211, 146,  48, 232, 185,
     47, 182, 230, 205
  ])
  // The string 'GoodCommitment' as utf-8 bytes
  // prettier-ignore
  const plaintext = new Uint8Array([
    71, 111, 111, 100,  67,
   111, 109, 109, 105, 116,
   109, 101, 110, 116
 ])

  class TestKeyring extends KeyringWebCrypto {
    async _onEncrypt(): Promise<WebCryptoEncryptionMaterial> {
      throw new Error('I should never see this error')
    }
    async _onDecrypt(material: WebCryptoDecryptionMaterial) {
      const unencryptedDataKey = dataKey
      const trace = {
        keyNamespace: 'k',
        keyName: 'k',
        flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
      }

      return importForWebCryptoDecryptionMaterial(
        material.setUnencryptedDataKey(unencryptedDataKey, trace)
      )
    }
  }

  it('can decrypt test vector', async () => {
    const keyring = new TestKeyring()
    const test = await decrypt(keyring, testVector)
    expect(test.plaintext).to.deep.equal(plaintext)
    expect(test.messageHeader.version).to.equal(MessageFormat.V2)
    expect(test.messageHeader.suiteId).to.equal(1144)
  })
})
