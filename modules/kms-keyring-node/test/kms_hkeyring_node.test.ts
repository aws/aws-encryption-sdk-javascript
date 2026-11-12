// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AwsEsdkKeyObject,
  EncryptedDataKey,
  EncryptionContext,
  KeyringTraceFlag,
  NodeBranchKeyMaterial,
  NodeDecryptionMaterial,
  NodeEncryptionMaterial,
  unwrapDataKey,
} from '@aws-crypto/material-management'
import {
  IKmsHierarchicalKeyRingNode,
  KmsHierarchicalKeyRingNode,
} from '../src/kms_hkeyring_node'
import chai, { expect } from 'chai'
import {
  BRANCH_KEY,
  BRANCH_KEY_ID,
  BRANCH_KEY_ID_A,
  BRANCH_KEY_ID_B,
  CASE_A,
  CASE_B,
  DEFAULT_EC,
  EC_A,
  EC_B,
  KEYSTORE,
  TEST_ESDK_ALG_SUITE,
  TTL,
} from './fixtures'
import {
  CIPHERTEXT_STRUCTURE,
  DECRYPT_FLAGS,
  ENCRYPT_FLAGS,
  PROVIDER_ID_HIERARCHY,
} from '../src/constants'
import { BranchKeyIdSupplier } from '@aws-crypto/kms-keyring'
import chaiAsPromised from 'chai-as-promised'
chai.use(chaiAsPromised)

export class DummyBranchKeyIdSupplier implements BranchKeyIdSupplier {
  private _cases: { [key: string]: string } = {
    [CASE_A]: BRANCH_KEY_ID_A,
    [CASE_B]: BRANCH_KEY_ID_B,
  }

  getBranchKeyId(encryptionContext: EncryptionContext): string {
    if (BRANCH_KEY in encryptionContext) {
      const c = encryptionContext[BRANCH_KEY]
      if (c in this._cases) {
        return this._cases[c]
      }
    }

    throw new Error("Can't determine branchKeyId from context")
  }
}
export const BRANCH_KEY_ID_SUPPLIER = new DummyBranchKeyIdSupplier()

// a function to deep copy branch key material. This is needed so that the mock
// key store can return new branch key material every time
export function deepCopyBranchKeyMaterial(material: NodeBranchKeyMaterial) {
  const branchKey = Buffer.from(material.branchKey())
  const branchKeyVersionAsString = material.branchKeyVersion.toString('utf-8')
  const encryptionContext = { ...material.encryptionContext }
  const branchKeyIdentifier = material.branchKeyIdentifier
  return new NodeBranchKeyMaterial(
    branchKey,
    branchKeyIdentifier,
    branchKeyVersionAsString,
    encryptionContext
  )
}

// a util function to test onEncrypt and expect an error while ensuring the
// encryption material is not modified
export async function testOnEncryptError(
  hkr: IKmsHierarchicalKeyRingNode,
  encryptionMaterial: NodeEncryptionMaterial,
  errorMessage: string
) {
  const expectedNumberOfEdks = encryptionMaterial.encryptedDataKeys.length
  const expectedNumberOfTraces = encryptionMaterial.keyringTrace.length
  const alreadyHasPdk = encryptionMaterial.hasUnencryptedDataKey

  await expect(hkr.onEncrypt(encryptionMaterial)).to.be.rejectedWith(
    errorMessage
  )

  expect(encryptionMaterial.encryptedDataKeys).to.have.lengthOf(
    expectedNumberOfEdks
  )
  expect(encryptionMaterial.keyringTrace).to.have.lengthOf(
    expectedNumberOfTraces
  )
  expect(encryptionMaterial.hasUnencryptedDataKey).to.equal(alreadyHasPdk)
}

// a util test function to run onEncrypt. It also makes sure that the correct
// modifications are made to the encryption material whether we are generating an pdk
// and wrapping it into an edk, OR just wrapping an existing pdk into a new edk
export async function testOnEncrypt(
  hkr: IKmsHierarchicalKeyRingNode,
  wrappingKeyName: string,
  encryptionMaterial: NodeEncryptionMaterial
) {
  // expect 1 more edk to be generated
  const expectedNumberOfEdks = encryptionMaterial.encryptedDataKeys.length + 1
  // we expect one more trace to be added from the new edk. If there is also no
  // pdk, there will be an extra generation trace for this
  const expectedNumberOfTraces =
    encryptionMaterial.keyringTrace.length +
    (encryptionMaterial.hasUnencryptedDataKey ? 1 : 2)

  const alreadyHasPdk = encryptionMaterial.hasUnencryptedDataKey
  let initialPdk: Uint8Array | AwsEsdkKeyObject | undefined = undefined
  if (alreadyHasPdk) {
    initialPdk = encryptionMaterial.getUnencryptedDataKey()
  }

  await hkr.onEncrypt(encryptionMaterial)

  expect(encryptionMaterial.encryptedDataKeys).to.have.lengthOf(
    expectedNumberOfEdks
  )

  // whether or not a pdk was generated or not, there should be a pdk
  expect(encryptionMaterial.hasUnencryptedDataKey).to.be.true
  if (alreadyHasPdk) {
    const encryptedPdk = encryptionMaterial.getUnencryptedDataKey()
    expect(encryptedPdk).to.equal(initialPdk)
  } else {
    // the pdk should have a length conforming to the key length specified by the
    // algorithm suite
    const encryptedPdk = unwrapDataKey(
      encryptionMaterial.getUnencryptedDataKey()
    )
    expect(encryptedPdk).to.have.lengthOf(
      encryptionMaterial.suite.keyLengthBytes
    )
  }

  expect(encryptionMaterial.keyringTrace).to.have.lengthOf(
    expectedNumberOfTraces
  )

  // the edk created from this onEncrypt call is the most recent one. Thus, it
  // will be the last edk
  const lastEdk = encryptionMaterial.encryptedDataKeys[expectedNumberOfEdks - 1]
  const {
    providerId: edkProviderId,
    providerInfo: edkProviderInfo,
    encryptedDataKey: edkCiphertext,
  } = lastEdk
  const edkExpectedLength =
    CIPHERTEXT_STRUCTURE.saltLength +
    CIPHERTEXT_STRUCTURE.ivLength +
    CIPHERTEXT_STRUCTURE.branchKeyVersionCompressedLength +
    CIPHERTEXT_STRUCTURE.authTagLength +
    encryptionMaterial.suite.keyLengthBytes

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=test
  //# Otherwise, OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key)
  //# to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
  //# - [ciphertext](../structures.md#ciphertext): MUST be serialized as the [hierarchical keyring ciphertext](#ciphertext)
  //# - [key provider id](../structures.md#key-provider-id): MUST be UTF8 Encoded "aws-kms-hierarchy"
  //# - [key provider info](../structures.md#key-provider-information): MUST be the UTF8 Encoded AWS DDB response `branch-key-id`
  expect(edkProviderId).to.equal(PROVIDER_ID_HIERARCHY)
  expect(edkProviderInfo).to.equal(wrappingKeyName)
  expect(edkCiphertext).to.have.lengthOf(edkExpectedLength)

  // if this is the first onEncrypt of the encryption material's lifetime,
  // traces will look like [generate, encrypt]. Otherwise, it will look like
  // [generate, encrypt, encrypt, ...]
  expect(expectedNumberOfTraces).to.be.greaterThanOrEqual(2)

  const encryptTrace =
    encryptionMaterial.keyringTrace[expectedNumberOfTraces - 1]
  const generateTrace = encryptionMaterial.keyringTrace[0]

  expect(generateTrace.flags).to.equal(
    KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
  )
  expect(generateTrace.keyNamespace).to.equal(PROVIDER_ID_HIERARCHY)
  expect(generateTrace.keyName).to.equal(wrappingKeyName)

  expect(encryptTrace.flags).to.equal(ENCRYPT_FLAGS)
  expect(encryptTrace.keyNamespace).to.equal(PROVIDER_ID_HIERARCHY)
  expect(encryptTrace.keyName).to.equal(wrappingKeyName)
}

// a util function to test onDecrypt and expect an error while ensuring the
// decryption material is not modified
export async function testOnDecryptError(
  hkr: IKmsHierarchicalKeyRingNode,
  edks: EncryptedDataKey[],
  decryptionMaterial: NodeDecryptionMaterial,
  errorMessage?: string,
  errorMessages?: string[]
) {
  const expectedNumberOfTraces = decryptionMaterial.keyringTrace.length
  const alreadyHasPdk = decryptionMaterial.hasUnencryptedDataKey

  if (errorMessage) {
    await expect(hkr.onDecrypt(decryptionMaterial, edks)).to.be.rejectedWith(
      errorMessage as string
    )
  } else {
    try {
      await hkr.onDecrypt(decryptionMaterial, edks)
    } catch (error) {
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
      //= type=test
      //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
      //# then it MUST yield an error that includes all the collected errors
      //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
      const errMsg = (error as Error).message
      for (const expectedError of errorMessages as string[]) {
        expect(errMsg.includes(expectedError)).to.be.true
      }
    }
  }

  expect(decryptionMaterial.keyringTrace).to.have.lengthOf(
    expectedNumberOfTraces
  )
  expect(decryptionMaterial.hasUnencryptedDataKey).to.equal(alreadyHasPdk)
}

// a util function that runs onDecrypt. This function ensures that the
// decryption material is accurately modified
export async function testOnDecrypt(
  hkr: IKmsHierarchicalKeyRingNode,
  expectedEncryptedPdk: Uint8Array,
  edks: EncryptedDataKey[],
  wrappingKeyName: string,
  decryptionMaterial: NodeDecryptionMaterial
) {
  // onDecrypt will add exactly 1 extra decrypt trace flag
  const expectedNumberOfTraces = decryptionMaterial.keyringTrace.length + 1

  await hkr.onDecrypt(decryptionMaterial, edks)

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
  //= type=test
  //# If a decryption succeeds, this keyring MUST
  //# add the resulting plaintext data key to the decryption materials and return the modified materials.
  // if onDecrypt is successful, it should always have the pdk
  expect(decryptionMaterial.hasUnencryptedDataKey).equals(true)
  const decryptedPdk = unwrapDataKey(decryptionMaterial.getUnencryptedDataKey())
  // this pdk that was unwrapped during onDecrypt should be the expected pdk
  expect(expectedEncryptedPdk).to.deep.equal(decryptedPdk)

  expect(decryptionMaterial.keyringTrace).to.have.lengthOf(
    expectedNumberOfTraces
  )

  // the trace left by this onDecrypt call should be a decrypt flag
  const decryptTrace =
    decryptionMaterial.keyringTrace[expectedNumberOfTraces - 1]
  expect(decryptTrace.keyNamespace).to.equal(PROVIDER_ID_HIERARCHY)
  expect(decryptTrace.keyName).to.equal(wrappingKeyName)
  expect(decryptTrace.flags).to.equal(DECRYPT_FLAGS)
}

// this util function runs a roundtrip test with the provided encryption and
// decryption material, acting as a small CMM
export async function testRoundtrip(
  hkr: IKmsHierarchicalKeyRingNode,
  wrappingKeyName: string,
  encryptionMaterial: NodeEncryptionMaterial = new NodeEncryptionMaterial(
    TEST_ESDK_ALG_SUITE,
    DEFAULT_EC
  ),
  decryptionMaterial: NodeDecryptionMaterial = new NodeDecryptionMaterial(
    encryptionMaterial.suite,
    encryptionMaterial.encryptionContext
  )
) {
  // run onEncrypt with verification
  await testOnEncrypt(hkr, wrappingKeyName, encryptionMaterial)

  // get the pdk and edks
  const encryptedPdk = unwrapDataKey(encryptionMaterial.getUnencryptedDataKey())
  const edks = encryptionMaterial.encryptedDataKeys

  // try to decrypt the edks and expect to obtain the pdk from the encryption
  // material
  await testOnDecrypt(
    hkr,
    encryptedPdk,
    edks,
    wrappingKeyName,
    decryptionMaterial
  )
}

describe('KmsHierarchicalKeyRingNode: MPL tests', () => {
  it('Test Hierarchy Client ESDK Suite', async () => {
    const branchKeyId = BRANCH_KEY_ID
    const keyStore = KEYSTORE
    const cacheLimitTtl = TTL
    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyId,
      keyStore,
      cacheLimitTtl,
    })
    let encryptionMaterial = new NodeEncryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      DEFAULT_EC
    )

    await testRoundtrip(hkr, branchKeyId, encryptionMaterial)

    // test with an initial pdk already existing
    const initialPdk = new Uint8Array(
      unwrapDataKey(encryptionMaterial.getUnencryptedDataKey())
    )
    encryptionMaterial = new NodeEncryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      DEFAULT_EC
    ).setUnencryptedDataKey(initialPdk, {
      keyName: branchKeyId,
      keyNamespace: PROVIDER_ID_HIERARCHY,
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })

    await testRoundtrip(hkr, branchKeyId, encryptionMaterial)
  })

  it('Test branch key id supplier', async () => {
    const branchKeyIdSupplier = BRANCH_KEY_ID_SUPPLIER
    const keyStore = KEYSTORE
    const cacheLimitTtl = TTL
    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyIdSupplier,
      keyStore,
      cacheLimitTtl,
    })
    const encryptionMaterialA = new NodeEncryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      EC_A
    )
    const encryptionMaterialB = new NodeEncryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      EC_B
    )

    await testRoundtrip(hkr, BRANCH_KEY_ID_A, encryptionMaterialA)
    await testRoundtrip(hkr, BRANCH_KEY_ID_B, encryptionMaterialB)
  })

  it('Test invalid data key error', async () => {
    const branchKeyIdSupplier = BRANCH_KEY_ID_SUPPLIER
    const keyStore = KEYSTORE
    const cacheLimitTtl = TTL
    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyIdSupplier,
      keyStore,
      cacheLimitTtl,
    })
    const encryptionMaterial = new NodeEncryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      EC_A
    )
    const decyrptionMaterial = new NodeDecryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      EC_B
    )

    // encrypt the generated pdk using branch key A as a wrapper
    await testOnEncrypt(hkr, BRANCH_KEY_ID_A, encryptionMaterial)

    const encryptedPdk = unwrapDataKey(
      encryptionMaterial.getUnencryptedDataKey()
    )
    const edks = encryptionMaterial.encryptedDataKeys

    // now we want to decrypt the edk with branch key B. However, the edk given
    // to onDecrypt knows that it was encrypted with branch key A. The edk
    // doesn't even pass the filter to attempt decryption.
    await expect(
      testOnDecrypt(
        hkr,
        encryptedPdk,
        edks,
        BRANCH_KEY_ID_B,
        decyrptionMaterial
      )
    ).to.be.rejectedWith(
      "There must be an encrypted data key that matches this keyring's configuration"
    )
  })
})
