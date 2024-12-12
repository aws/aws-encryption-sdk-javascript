// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CIPHERTEXT_STRUCTURE, PROVIDER_ID_HIERARCHY } from '../src/constants'
import {
  BRANCH_KEY_ACTIVE_VERSION,
  BRANCH_KEY_ID,
  BRANCH_KEY_ID_A,
  BRANCH_KEY_ID_B,
  DEFAULT_EC,
  EC_A,
  KEYSTORE,
  TEST_ESDK_ALG_SUITE,
  TTL,
} from './fixtures'
import { v4 } from 'uuid'
import { uuidv4ToCompressedBytes } from '../src/kms_hkeyring_node_helpers'
import {
  EncryptedDataKey,
  NodeBranchKeyMaterial,
  NodeDecryptionMaterial,
  NodeEncryptionMaterial,
  unwrapDataKey,
} from '@aws-crypto/material-management'
import { KmsHierarchicalKeyRingNode } from '../src/kms_hkeyring_node'
import chai, { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import Sinon from 'sinon'
import { KMSClient } from '@aws-sdk/client-kms'
import { DynamoDBClient } from '@aws-sdk/client-dynamodb'
import {
  BRANCH_KEY_ID_SUPPLIER,
  deepCopyBranchKeyMaterial,
  testOnDecrypt,
  testOnDecryptError,
  testOnEncrypt,
} from './kms_hkeyring_node.test'
import { BranchKeyStoreNode, KeyStoreInfoOutput } from '@aws-crypto/branch-keystore-node'
chai.use(chaiAsPromised)

// an edk that can't even be destructured according to any alg suite
const malformedEdkCiphertext = new Uint8Array(Buffer.alloc(1))

// expected length of well-formed edk ciphertexts
const ciphertextLength =
  CIPHERTEXT_STRUCTURE.saltLength +
  CIPHERTEXT_STRUCTURE.ivLength +
  CIPHERTEXT_STRUCTURE.branchKeyVersionCompressedLength +
  TEST_ESDK_ALG_SUITE.keyLengthBytes +
  CIPHERTEXT_STRUCTURE.authTagLength

// an edk whose compressed branch key version cannot be decompressed as a uuidv4
const badUuidEdkCiphertext = new Uint8Array(Buffer.alloc(ciphertextLength))

// an edk whose branch key version can be decompressed but is non-existent in
// the keystore
const nonExistentBranchKeyVersion = v4()
const nonExistentBranchKeyVersionEdkCiphertext = new Uint8Array(
  badUuidEdkCiphertext
)
nonExistentBranchKeyVersionEdkCiphertext.set(
  uuidv4ToCompressedBytes(nonExistentBranchKeyVersion),
  CIPHERTEXT_STRUCTURE.saltLength + CIPHERTEXT_STRUCTURE.ivLength
)

// an edk whose ciphertext cannot be unwrapped
const existingBranchKeyVersion = BRANCH_KEY_ACTIVE_VERSION
const nonUnwrappableEdkCiphertext = new Uint8Array(badUuidEdkCiphertext)
nonUnwrappableEdkCiphertext.set(
  uuidv4ToCompressedBytes(existingBranchKeyVersion),
  CIPHERTEXT_STRUCTURE.saltLength + CIPHERTEXT_STRUCTURE.ivLength
)

const badCiphertexts = [
  malformedEdkCiphertext,
  badUuidEdkCiphertext,
  nonExistentBranchKeyVersionEdkCiphertext,
  nonUnwrappableEdkCiphertext,
]

const branchKeyId = BRANCH_KEY_ID
const branchKeyIdSupplier = BRANCH_KEY_ID_SUPPLIER
const originalKeyStore = KEYSTORE
const cacheLimitTtl = TTL

// create bad edks that pass the filter but fail decryption for different
// reasons due to their bad ciphertexts
const badEdks = badCiphertexts.map(
  (badCiphertext) =>
    new EncryptedDataKey({
      providerId: PROVIDER_ID_HIERARCHY,
      providerInfo: branchKeyId,
      encryptedDataKey: badCiphertext,
    })
)

// before all tests run, get the active and versioned branch key materials
let activeBranchKeyMaterial: NodeBranchKeyMaterial
let activeVersion: string
let versionedBranchKeyMaterial: NodeBranchKeyMaterial
before(async function () {
  activeBranchKeyMaterial = await originalKeyStore.getActiveBranchKey(
    branchKeyId
  )
  activeVersion = activeBranchKeyMaterial.branchKeyVersion.toString('utf-8')

  versionedBranchKeyMaterial = await originalKeyStore.getBranchKeyVersion(
    branchKeyId,
    activeVersion
  )
})

describe('KmsHierarchicalKeyRingNode: decrypt EDK order', () => {
  let kmsSendSpy: any
  let ddbSendSpy: any
  let keyStore: Sinon.SinonStubbedInstance<BranchKeyStoreNode>

  beforeEach(() => {
    keyStore = Sinon.createStubInstance(BranchKeyStoreNode)
    kmsSendSpy = Sinon.spy(KMSClient.prototype, 'send')
    ddbSendSpy = Sinon.spy(DynamoDBClient.prototype, 'send')

    keyStore.getActiveBranchKey.callsFake(async function (id: string) {
      if (id === branchKeyId) {
        return deepCopyBranchKeyMaterial(activeBranchKeyMaterial)
      } else {
        throw new Error(
          `A branch key record with branch-key-id=${id} and type=branch:ACTIVE was not found in DynamoDB`
        )
      }
    })

    keyStore.getBranchKeyVersion.callsFake(async function (
      id: string,
      branchKeyVersion: string
    ) {
      if (branchKeyId === id && branchKeyVersion === activeVersion) {
        kmsSendSpy.callCount += 1
        ddbSendSpy.callCount += 1
        return deepCopyBranchKeyMaterial(versionedBranchKeyMaterial)
      } else {
        ddbSendSpy.callCount += 1
        throw new Error(
          `A branch key record with branch-key-id=${id} and type=branch:version:${branchKeyVersion} was not found in DynamoDB`
        )
      }
    })

    keyStore.getKeyStoreInfo.callsFake(function(): KeyStoreInfoOutput {
      return {
        keystoreId: "keyStoreId",
        keystoreTableName: "keystoreTableName",
        logicalKeyStoreName: "logicalKeyStoreName",
        grantTokens: [],
        // This is not used by any tests
        kmsConfiguration: null as any
      }
    })
  })

  afterEach(() => {
    keyStore.getActiveBranchKey.reset()
    keyStore.getBranchKeyVersion.reset()
    kmsSendSpy.restore()
    ddbSendSpy.restore()
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
  //= type=test
  //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration. For the encrypted data key to match:
  //# - Its provider ID MUST match the UTF8 Encoded value of “aws-kms-hierarchy”.
  //# - Deserialize the key provider info, if deserialization fails the next EDK in the set MUST be attempted.
  //#   - The deserialized key provider info MUST be UTF8 Decoded and MUST match this keyring's configured `Branch Key Identifier`.
  it('Precondition: There must be an encrypted data key that matches this keyring configuration', async () => {
    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyIdSupplier,
      keyStore,
      cacheLimitTtl,
    })
    const badEdkProviderId = `bad-${PROVIDER_ID_HIERARCHY}`

    const badEdks: EncryptedDataKey[] = [
      ...Array(5).fill(
        new EncryptedDataKey({
          providerInfo: BRANCH_KEY_ID_A,
          providerId: badEdkProviderId,
          encryptedDataKey: malformedEdkCiphertext,
        })
      ),
      // onDecrypt wants to use branch key A for unwrapping. Edks with provider
      // info of branch key id B will not match the keyring configuration and
      // fail the filter
      ...Array(5).fill(
        new EncryptedDataKey({
          providerInfo: BRANCH_KEY_ID_B,
          providerId: PROVIDER_ID_HIERARCHY,
          encryptedDataKey: malformedEdkCiphertext,
        })
      ),
    ]

    const decryptionMaterial = new NodeDecryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      EC_A // use branch key A for decryption
    )

    await testOnDecryptError(
      hkr,
      badEdks,
      decryptionMaterial,
      "There must be an encrypted data key that matches this keyring's configuration"
    )
  })

  it('Precondition: The edk ciphertext must have the correct length', async () => {
    // this test is already covered in the test after, but is here for
    // precondition compliance checks

    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyId,
      keyStore,
      cacheLimitTtl,
    })
    const decryptionMaterial = new NodeDecryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      DEFAULT_EC
    )
    const expectedError = `The encrypted data key ciphertext must be ${ciphertextLength} bytes long`

    await testOnDecryptError(hkr, [badEdks[0]], decryptionMaterial, undefined, [
      expectedError,
    ])
  })

  it('None of the edks can be decrypted', async () => {
    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyId,
      keyStore,
      cacheLimitTtl,
    })
    const decryptionMaterial = new NodeDecryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      DEFAULT_EC
    )

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //= type=test
    //# For each encrypted data key in the filtered set, one at a time, OnDecrypt MUST attempt to decrypt the encrypted data key.
    //# If this attempt results in an error, then these errors MUST be collected.
    const expectedErrors = [
      `Error #1 \n Error: The encrypted data key ciphertext must be ${ciphertextLength} bytes long`,
      'Error #2 \n Error: Input must represent a uuidv4',
      `Error #3 \n Error: A branch key record with branch-key-id=${branchKeyId} and type=branch:version:${nonExistentBranchKeyVersion} was not found in DynamoDB`,
      'Error #4 \n Error: Unsupported state or unable to authenticate data',
    ]

    await testOnDecryptError(
      hkr,
      badEdks,
      decryptionMaterial,
      undefined,
      expectedErrors
    )
  })

  it('short circuit on the first success', async () => {
    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyId,
      keyStore,
      cacheLimitTtl,
    })

    const goodEdks = []
    const pdks = []

    // for every bad edk, we make a "good" decryptable edk
    // by the end of these onEncrypt calls, the active branch key material will
    // be in the CMC
    for (let i = 0; i < badEdks.length; i++) {
      // create fresh encryption material such that a different pdk will be
      // generated, giving us a different edk each time
      const encryptionMaterial = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )

      await testOnEncrypt(hkr, branchKeyId, encryptionMaterial)

      const edk = encryptionMaterial.encryptedDataKeys[0]
      const generatedPdk = unwrapDataKey(
        encryptionMaterial.getUnencryptedDataKey()
      )

      goodEdks.push(edk)
      pdks.push(generatedPdk)
    }

    const edks = [...badEdks, ...goodEdks]
    const decryptionMaterial = new NodeDecryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      DEFAULT_EC
    )

    // the first two bad edks won't even make it past the filter

    // the 3rd bad edk will attempt to get nonexistent versioned branch key
    // material from DDB but fail (1 DDB call, 0 KMS calls)

    // the 4th bad edk will get the versioned branch key material and cache it
    // but fail at unwrapping (1 more DDB call, 1 more KMS call)

    // then the 1st good edk wants the same versioned branch key material, so it
    // gets the materail from the cache (0 more DDB calls, 0 more KMS calls).
    // This will be a successful decryption and we short circuit.

    // the other good edks won't even be attempted because of short circuiting.
    // Thus the pdk in the decryption material should match the first generated pdk
    await testOnDecrypt(hkr, pdks[0], edks, branchKeyId, decryptionMaterial)

    expect(kmsSendSpy.callCount).equals(1)
    expect(ddbSendSpy.callCount).equals(2)
  })
})
