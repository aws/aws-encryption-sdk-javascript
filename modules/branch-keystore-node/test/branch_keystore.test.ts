// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import chai, { expect } from 'chai'
import {
  BranchKeyStoreNode,
  isIBranchKeyStoreNode,
} from '../src/branch_keystore'
import { DynamoDBKeyStorage } from '../src/dynamodb_key_storage'
import { validate, v4, version } from 'uuid'
import chaiAsPromised from 'chai-as-promised'
import {
  KMSClient,
  InvalidCiphertextException,
  IncorrectKeyException,
} from '@aws-sdk/client-kms'
import { DynamoDBClient } from '@aws-sdk/client-dynamodb'
import { getRegionFromIdentifier } from '@aws-crypto/kms-keyring'
import {
  BRANCH_KEY_ACTIVE_VERSION,
  BRANCH_KEY_ACTIVE_VERSION_UTF8_BYTES,
  BRANCH_KEY_ID,
  DDB_TABLE_NAME,
  INCORRECT_LOGICAL_NAME,
  KEY_ARN,
  KEY_ID,
  KMS_KEY_ALIAS,
  LOGICAL_KEYSTORE_NAME,
  LYING_BRANCH_KEY_DECRYPT_ONLY_VERSION,
  LYING_BRANCH_KEY_ID,
  POSTAL_HORN_BRANCH_KEY_ID,
  POSTAL_HORN_KEY_ARN,
} from './fixtures'
import {
  BRANCH_KEY_ACTIVE_TYPE,
  PARTITION_KEY,
  SORT_KEY,
} from '../src/constants'

chai.use(chaiAsPromised)
describe('Test Branch keystore', () => {
  it('Test type guard', () => {
    for (const keyStore of [null, undefined, 0, {}, '']) {
      expect(isIBranchKeyStoreNode(keyStore as any)).to.be.false
    }
  })

  describe('Test constructor', () => {
    const KMS_CONFIGURATION = { identifier: KEY_ARN }

    const BRANCH_KEYSTORE = new BranchKeyStoreNode({
      storage: { ddbTableName: DDB_TABLE_NAME },
      logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
      kmsConfiguration: KMS_CONFIGURATION,
    })

    const falseyValues = [false, 0, -0, 0n, '', null, undefined, NaN]
    const truthyValues = [[3, [], true], {}, 1, true, 'string']

    it('Precondition: DDB table name must be a string', () => {
      // all types of values except strings
      const badVals = [...falseyValues, ...truthyValues].filter(
        (v) => typeof v !== 'string'
      )

      for (const ddbTableName of badVals) {
        expect(
          () =>
            new BranchKeyStoreNode({
              storage: { ddbTableName: ddbTableName as any },
              logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
              kmsConfiguration: KMS_CONFIGURATION,
            })
        ).to.throw('DDB table name must be a string')
      }
    })

    it('Precondition: Logical keystore name must be a string', () => {
      // all types of values except strings
      const badVals = [...falseyValues, ...truthyValues].filter(
        (v) => typeof v !== 'string'
      )

      for (const logicalKeyStoreName of badVals) {
        expect(
          () =>
            new BranchKeyStoreNode({
              storage: { ddbTableName: DDB_TABLE_NAME },
              logicalKeyStoreName: logicalKeyStoreName as any,
              kmsConfiguration: KMS_CONFIGURATION,
            })
        ).to.throw('Logical keystore name must be a string')
      }
    })

    it('Precondition: KMS Configuration must be SRK', () => {
      // all types of values
      const badVals = [...falseyValues, ...truthyValues]

      for (const kmsConfiguration of badVals) {
        expect(
          () =>
            new BranchKeyStoreNode({
              storage: { ddbTableName: DDB_TABLE_NAME },
              logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
              kmsConfiguration: kmsConfiguration as any,
            })
        ).to.throw('KMS Configuration must be SRK')
      }
    })

    it('Precondition: KMS client must be a KMSClient', () => {
      // only truthy values because KMS client may be falsey
      for (const kmsClient of truthyValues) {
        expect(
          () =>
            new BranchKeyStoreNode({
              storage: { ddbTableName: DDB_TABLE_NAME },
              logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
              kmsConfiguration: KMS_CONFIGURATION,
              keyManagement: { kmsClient: kmsClient as any },
            })
        ).to.throw('KMS client must be a KMSClient')
      }
    })

    it('Precondition: DDB client must be a DynamoDBClient', () => {
      // only truthy values because DDB client may be falsey
      for (const ddbClient of truthyValues) {
        expect(
          () =>
            new BranchKeyStoreNode({
              storage: {
                ddbTableName: DDB_TABLE_NAME,
                ddbClient: ddbClient as any,
              },
              logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
              kmsConfiguration: KMS_CONFIGURATION,
            })
        ).to.throw('DDB client must be a DynamoDBClient')
      }
    })

    it('Precondition: Keystore id must be a string', () => {
      // only truthy values that are not strings because keystore id may be
      // falsey
      const badVals = truthyValues.filter((v) => typeof v !== 'string')
      for (const keyStoreId of badVals) {
        expect(
          () =>
            new BranchKeyStoreNode({
              storage: { ddbTableName: DDB_TABLE_NAME },
              logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
              kmsConfiguration: KMS_CONFIGURATION,
              keyStoreId: keyStoreId as any,
            })
        ).to.throw('Keystore id must be a string')
      }
    })

    it('Precondition: Grant tokens must be a string array', () => {
      // use only truthy values because grantTokens may be falsey
      for (const grantTokens of truthyValues) {
        expect(
          () =>
            new BranchKeyStoreNode({
              storage: { ddbTableName: DDB_TABLE_NAME },
              logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
              kmsConfiguration: KMS_CONFIGURATION,
              keyManagement: { grantTokens: grantTokens as any },
            })
        ).to.throw('Grant tokens must be a string array')
      }
    })

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-grant-tokens
    //= type=test
    //# A list of AWS KMS [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
    it('Postcondition: If unprovided, the grant tokens are undefined', () => {
      for (const grantTokens of falseyValues) {
        expect(
          new BranchKeyStoreNode({
            storage: { ddbTableName: DDB_TABLE_NAME },
            logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
            kmsConfiguration: KMS_CONFIGURATION,
            keyManagement: { grantTokens: grantTokens as any },
          }).grantTokens
        ).to.equal(undefined)
      }
    })

    it('Invalid KmsKeyArn config', () => {
      const kmsClient = new KMSClient({})
      const ddbClient = new DynamoDBClient({})
      expect(() => {
        const kmsConfig = { identifier: KEY_ID }
        return new BranchKeyStoreNode({
          storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },
          logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
          kmsConfiguration: kmsConfig,
          keyManagement: { kmsClient },
        })
      }).to.throw(
        `${KEY_ID} must be a well-formed AWS KMS non-alias resource arn`
      )
    })

    it('Invalid KmsKeyArn Alias config', () => {
      const kmsClient = new KMSClient({})
      const ddbClient = new DynamoDBClient({})
      expect(() => {
        const kmsConfig = { identifier: KMS_KEY_ALIAS }
        return new BranchKeyStoreNode({
          storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },
          logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
          kmsConfiguration: kmsConfig,
          keyManagement: { kmsClient },
        })
      }).to.throw(
        `${KMS_KEY_ALIAS} must be a well-formed AWS KMS non-alias resource arn`
      )
    })

    it('Valid config', () => {
      const kmsClient = new KMSClient({})
      const ddbClient = new DynamoDBClient({})
      const kmsConfig = { identifier: KEY_ID }
      const keyStore = new BranchKeyStoreNode({
        storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },
        logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
        kmsConfiguration: kmsConfig,
        keyManagement: { kmsClient },
      })

      expect(
        validate(keyStore.keyStoreId) && version(keyStore.keyStoreId) === 4
      ).equals(true)
      // expect(keyStore.ddbTableName).equals(DDB_TABLE_NAME)
      expect(keyStore.kmsConfiguration).equals(kmsConfig)
    })

    it('Test valid config with no clients', () => {
      const kmsClient = new KMSClient({})
      const ddbClient = new DynamoDBClient({})
      const kmsConfig = { identifier: KEY_ID }

      // test with no kms client supplied
      expect(
        () =>
          new BranchKeyStoreNode({
            storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },
            logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
            kmsConfiguration: kmsConfig,
          })
      ).to.not.throw()

      // test with no ddb client supplied
      expect(
        () =>
          new BranchKeyStoreNode({
            storage: { ddbTableName: DDB_TABLE_NAME },
            logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
            kmsConfiguration: kmsConfig,
            keyManagement: { kmsClient },
          })
      ).to.not.throw()

      // test with no clients supplied
      expect(
        () =>
          new BranchKeyStoreNode({
            storage: { ddbTableName: DDB_TABLE_NAME },
            logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
            kmsConfiguration: kmsConfig,
          })
      ).to.not.throw()
    })

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#keystore-id
    //= type=test
    //# The Identifier for this KeyStore.
    //# If one is not supplied, then a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt) MUST be used.
    it('Postcondition: If unprovided, the keystore id is a generated valid uuidv4', () => {
      for (const keyStoreId of falseyValues) {
        const { keyStoreId: id } = new BranchKeyStoreNode({
          storage: { ddbTableName: DDB_TABLE_NAME },
          logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
          kmsConfiguration: KMS_CONFIGURATION,
          keyStoreId: keyStoreId as any,
        })

        expect(validate(id) && version(id) === 4).equals(true)
      }
    })

    it('Postcondition: If unprovided, the DDB client is configured', async () => {
      for (const ddbClient of falseyValues) {
        const { storage } = new BranchKeyStoreNode({
          storage: {
            ddbTableName: DDB_TABLE_NAME,
            ddbClient: ddbClient as any,
          },
          logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
          kmsConfiguration: KMS_CONFIGURATION,
        })

        expect(storage instanceof DynamoDBKeyStorage).to.equals(true)
        expect(
          await (storage as DynamoDBKeyStorage).ddbClient.config.region()
        ).to.equal(getRegionFromIdentifier(KEY_ARN))
      }
    })

    it('Postcondition: If unprovided, the KMS client is configured', async () => {
      for (const kmsClient of falseyValues) {
        const { kmsClient: client } = new BranchKeyStoreNode({
          storage: { ddbTableName: DDB_TABLE_NAME },
          logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
          kmsConfiguration: KMS_CONFIGURATION,
          keyManagement: { kmsClient: kmsClient as any },
        })

        expect(await client.config.region()).to.equal(
          getRegionFromIdentifier(KEY_ARN)
        )
      }
    })

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#table-name
    //= type=test
    //# The table name of the DynamoDb table that backs this Keystore.
    it('Null table name provided', () => {
      expect(
        () =>
          new BranchKeyStoreNode({
            storage: { ddbTableName: '' },
            logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
            kmsConfiguration: KMS_CONFIGURATION,
          })
      ).to.throw('DynamoDb table name required')
    })

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#logical-keystore-name
    //= type=test
    //# This name is cryptographically bound to all data stored in this table,
    //# and logically separates data between different tables.
    //# The logical keystore name MUST be bound to every created key.
    //# There needs to be a one to one mapping between DynamoDB Table Names and the Logical KeyStore Name.
    //# This value can be set to the DynamoDB table name itself, but does not need to.
    //# Controlling this value independently enables restoring from DDB table backups
    //# even when the table name after restoration is not exactly the same.
    it('Null logical keystore name provided', () => {
      expect(
        () =>
          new BranchKeyStoreNode({
            storage: { ddbTableName: DDB_TABLE_NAME },
            logicalKeyStoreName: '',
            kmsConfiguration: KMS_CONFIGURATION,
          })
      ).to.throw('Logical Keystore name required')
    })

    describe('Test proper init', () => {
      it('KMS Configuration is immutable', () => {
        expect(Object.isFrozen(BRANCH_KEYSTORE.kmsConfiguration)).equals(true)
      })

      it('Keystore is immutable', () => {
        expect(Object.isFrozen(BRANCH_KEYSTORE)).equals(true)
      })

      it('Attributes are correct', () => {
        const kmsClient = new KMSClient({
          region: getRegionFromIdentifier(KEY_ARN),
        })
        const ddbClient = new DynamoDBClient({
          region: getRegionFromIdentifier(KEY_ARN),
        })
        const keyStoreId = v4()
        const grantTokens = [] as string[]
        const test = new BranchKeyStoreNode({
          storage: { ddbTableName: DDB_TABLE_NAME, ddbClient: ddbClient },
          logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
          kmsConfiguration: KMS_CONFIGURATION,
          keyStoreId: keyStoreId,
          keyManagement: { kmsClient: kmsClient, grantTokens: grantTokens },
        })

        expect((test.storage as DynamoDBKeyStorage).ddbTableName).to.equal(
          DDB_TABLE_NAME
        )
        expect(test.logicalKeyStoreName).to.equal(LOGICAL_KEYSTORE_NAME)
        expect(test.kmsConfiguration).to.equal(KMS_CONFIGURATION)
        expect(test.kmsClient).to.equal(kmsClient)
        expect((test.storage as DynamoDBKeyStorage).ddbClient).to.equal(
          ddbClient
        )
        expect(test.keyStoreId).to.equal(keyStoreId)
        expect(test.grantTokens).to.equal(grantTokens)
      })
    })
  })

  // the following tests are all integration tests. These tests test
  // getActiveBranchKey and getBranchKeyVersion as a whole while making network
  // calls to DDB and KMS
  it('Test get active key', async () => {
    const kmsClient = new KMSClient({})
    const ddbClient = new DynamoDBClient({})
    const kmsConfig = { identifier: KEY_ID }
    const keyStore = new BranchKeyStoreNode({
      kmsConfiguration: kmsConfig,
      storage: { ddbTableName: DDB_TABLE_NAME, ddbClient: ddbClient },
      logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,

      keyManagement: { kmsClient: kmsClient },
    })

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //= type=test
    //# On invocation, the caller:
    //# - MUST supply a `branch-key-id`
    await expect(keyStore.getActiveBranchKey('')).to.be.rejectedWith(
      'MUST supply a string branch key id'
    )

    // test type checks
    await expect(
      keyStore.getActiveBranchKey(undefined as any)
    ).to.be.rejectedWith('MUST supply a string branch key id')
    await expect(keyStore.getActiveBranchKey(null as any)).to.be.rejectedWith(
      'MUST supply a string branch key id'
    )

    const branchKeyMaterials = await keyStore.getActiveBranchKey(BRANCH_KEY_ID)
    // expect(branchKeyMaterials.branchKeyIdentifier).equals(BRANCH_KEY_ID)
    expect(branchKeyMaterials.branchKeyVersion).deep.equals(
      BRANCH_KEY_ACTIVE_VERSION_UTF8_BYTES
    )
    expect(branchKeyMaterials.branchKey().length).equals(32)
  })

  it('Test get branch key version', async () => {
    const kmsClient = new KMSClient({})
    const ddbClient = new DynamoDBClient({})
    const kmsConfig = { identifier: KEY_ID }

    const keyStore = new BranchKeyStoreNode({
      kmsConfiguration: kmsConfig,
      logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
      storage: { ddbTableName: DDB_TABLE_NAME, ddbClient: ddbClient },

      keyManagement: { kmsClient: kmsClient },
    })

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //= type=test
    //# On invocation, the caller:
    //# - MUST supply a `branch-key-id`
    //# - MUST supply a `branchKeyVersion`
    await expect(
      keyStore.getBranchKeyVersion('', BRANCH_KEY_ACTIVE_VERSION)
    ).to.be.rejectedWith('MUST supply a string branch key id')
    await expect(
      keyStore.getBranchKeyVersion(BRANCH_KEY_ID, '')
    ).to.be.rejectedWith('MUST supply a string branch key version')

    // test type checks
    await expect(
      keyStore.getBranchKeyVersion(undefined as any, BRANCH_KEY_ACTIVE_VERSION)
    ).to.be.rejectedWith('MUST supply a string branch key id')
    await expect(
      keyStore.getBranchKeyVersion(null as any, BRANCH_KEY_ACTIVE_VERSION)
    ).to.be.rejectedWith('MUST supply a string branch key id')
    await expect(
      keyStore.getBranchKeyVersion(BRANCH_KEY_ID, undefined as any)
    ).to.be.rejectedWith('MUST supply a string branch key version')
    await expect(
      keyStore.getBranchKeyVersion(BRANCH_KEY_ID, null as any)
    ).to.be.rejectedWith('MUST supply a string branch key version')

    const branchKeyMaterials = await keyStore.getBranchKeyVersion(
      BRANCH_KEY_ID,
      BRANCH_KEY_ACTIVE_VERSION
    )
    expect(branchKeyMaterials.branchKeyIdentifier).equals(BRANCH_KEY_ID)
    expect(branchKeyMaterials.branchKeyVersion).deep.equals(
      BRANCH_KEY_ACTIVE_VERSION_UTF8_BYTES
    )
    expect(branchKeyMaterials.branchKey().length).equals(32)
  })

  it('Test get active key with incorrect kms key arn', async () => {
    const kmsClient = new KMSClient({})
    const ddbClient = new DynamoDBClient({})
    const kmsConfig = { identifier: KEY_ID }

    const keyStore = new BranchKeyStoreNode({
      kmsConfiguration: kmsConfig,
      logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
      storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },

      keyManagement: { kmsClient },
    })

    void (await expect(
      keyStore.getActiveBranchKey(POSTAL_HORN_BRANCH_KEY_ID)
    ).to.be.rejectedWith(
      'KMS ARN from DDB response item MUST be compatible with the configured KMS Key in the AWS KMS Configuration for this keystore'
    ))
  })

  it('Test get active key with wrong logical keystore name', async () => {
    const kmsClient = new KMSClient({})
    const ddbClient = new DynamoDBClient({})
    const kmsConfig = { identifier: KEY_ID }

    const keyStore = new BranchKeyStoreNode({
      kmsConfiguration: kmsConfig,
      logicalKeyStoreName: INCORRECT_LOGICAL_NAME,
      storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },

      keyManagement: { kmsClient },
    })

    void (await expect(
      keyStore.getActiveBranchKey(BRANCH_KEY_ID)
    ).to.be.rejectedWith(InvalidCiphertextException))
  })

  it('Test get active key does not exist fails', async () => {
    const kmsClient = new KMSClient({})
    const ddbClient = new DynamoDBClient({})
    const kmsConfig = { identifier: KEY_ID }

    const keyStore = new BranchKeyStoreNode({
      kmsConfiguration: kmsConfig,
      logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
      storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },

      keyManagement: { kmsClient },
    })

    void (await expect(
      keyStore.getActiveBranchKey('Robbie')
    ).to.be.rejectedWith(
      `A branch key record with ${PARTITION_KEY}=Robbie and ${SORT_KEY}=${BRANCH_KEY_ACTIVE_TYPE} was not found in DynamoDB`
    ))
  })

  it('Test get active key with no clients', async () => {
    const kmsConfig = { identifier: KEY_ID }
    const keyStore = new BranchKeyStoreNode({
      kmsConfiguration: kmsConfig,
      logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
      storage: { ddbTableName: DDB_TABLE_NAME },
    })

    const branchKeyMaterials = await keyStore.getActiveBranchKey(BRANCH_KEY_ID)
    expect(branchKeyMaterials.branchKey().length).equals(32)
  })

  it('Test get active key for lying branch key', async () => {
    const kmsClient = new KMSClient({})
    const ddbClient = new DynamoDBClient({})
    const kmsConfig = { identifier: POSTAL_HORN_KEY_ARN }

    const keyStore = new BranchKeyStoreNode({
      kmsConfiguration: kmsConfig,
      logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
      storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },

      keyManagement: { kmsClient },
    })

    void (await expect(
      keyStore.getActiveBranchKey(LYING_BRANCH_KEY_ID)
    ).to.be.rejectedWith(IncorrectKeyException))
  })

  it('Test get versioned key for lying branch key', async () => {
    const kmsClient = new KMSClient({})
    const ddbClient = new DynamoDBClient({})
    const kmsConfig = { identifier: POSTAL_HORN_KEY_ARN }

    const keyStore = new BranchKeyStoreNode({
      kmsConfiguration: kmsConfig,
      logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
      storage: { ddbTableName: DDB_TABLE_NAME, ddbClient },

      keyManagement: { kmsClient },
    })

    void (await expect(
      keyStore.getBranchKeyVersion(
        LYING_BRANCH_KEY_ID,
        LYING_BRANCH_KEY_DECRYPT_ONLY_VERSION
      )
    ).to.be.rejectedWith(IncorrectKeyException))
  })
})
