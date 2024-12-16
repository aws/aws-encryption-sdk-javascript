// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * This class is the KMS H-keyring. This class is within the kms-keyring-node
 * module because it is a KMS keyring variation. However, the KDF used in this
 * keyring's operations will only work in Node.js runtimes and not browser JS.
 * Thus, this H-keyring implementation is only Node compatible, and thus,
 * resides in a node module, not a browser module
 */

import {
  EncryptedDataKey,
  immutableClass,
  KeyringNode,
  needs,
  NodeAlgorithmSuite,
  NodeDecryptionMaterial,
  NodeEncryptionMaterial,
  readOnlyProperty,
  Catchable,
  DecryptionMaterial,
  isDecryptionMaterial,
} from '@aws-crypto/material-management'
import {
  BranchKeyMaterialEntry,
  CryptographicMaterialsCache,
  getLocalCryptographicMaterialsCache,
} from '@aws-crypto/cache-material'
import {
  destructureCiphertext,
  getBranchKeyId,
  getBranchKeyMaterials,
  getCacheEntryId,
  getPlaintextDataKey,
  wrapPlaintextDataKey,
  unwrapEncryptedDataKey,
  filterEdk,
  modifyEncryptionMaterial,
  modifyDencryptionMaterial,
  decompressBytesToUuidv4,
  stringToUtf8Bytes,
} from './kms_hkeyring_node_helpers'
import {
  BranchKeyStoreNode,
  isIBranchKeyStoreNode,
} from '@aws-crypto/branch-keystore-node'
import {
  BranchKeyIdSupplier,
  isBranchKeyIdSupplier,
} from '@aws-crypto/kms-keyring'
import { randomBytes } from 'crypto'

export interface KmsHierarchicalKeyRingNodeInput {
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=implication
  //# - MUST provide either a Branch Key Identifier or a [Branch Key Supplier](#branch-key-supplier)
  branchKeyId?: string
  branchKeyIdSupplier?: BranchKeyIdSupplier
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=implication
  //# - MUST provide a [Keystore](../branch-key-store.md)
  keyStore: BranchKeyStoreNode
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=implication
  //# - MUST provide a [cache limit TTL](#cache-limit-ttl)
  cacheLimitTtl: number
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=exception
  //# - MAY provide a [Cache Type](#cache-type)
  cache?: CryptographicMaterialsCache<NodeAlgorithmSuite>
  maxCacheSize?: number
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=implication
  //# - MAY provide a [Partition ID](#partition-id)
  partitionId?: string
}

export interface IKmsHierarchicalKeyRingNode extends KeyringNode {
  branchKeyId?: string
  branchKeyIdSupplier?: Readonly<BranchKeyIdSupplier>
  keyStore: Readonly<BranchKeyStoreNode>
  cacheLimitTtl: number
  _onEncrypt(material: NodeEncryptionMaterial): Promise<NodeEncryptionMaterial>
  _onDecrypt(
    material: NodeDecryptionMaterial,
    encryptedDataKeys: EncryptedDataKey[]
  ): Promise<NodeDecryptionMaterial>
  cacheEntryHasExceededLimits(entry: BranchKeyMaterialEntry): boolean
}

export class KmsHierarchicalKeyRingNode
  extends KeyringNode
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#interface
  //= type=implication
  //# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
  implements IKmsHierarchicalKeyRingNode
{
  public declare branchKeyId?: string
  public declare branchKeyIdSupplier?: Readonly<BranchKeyIdSupplier>
  public declare keyStore: Readonly<BranchKeyStoreNode>
  public declare _logicalKeyStoreName: Buffer
  public declare cacheLimitTtl: number
  public declare maxCacheSize?: number
  public declare _cmc: CryptographicMaterialsCache<NodeAlgorithmSuite>
  declare readonly _partition: Buffer

  constructor({
    branchKeyId,
    branchKeyIdSupplier,
    keyStore,
    cacheLimitTtl,
    cache,
    maxCacheSize,
    partitionId,
  }: KmsHierarchicalKeyRingNodeInput) {
    super()

    needs(
      !partitionId || typeof partitionId === 'string',
      'Partition id must be a string.'
    )

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
    //= type=implication
    //# The Partition ID MUST NOT be changed after initialization.
    readOnlyProperty(
      this,
      '_partition',

      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id-1
      //# It can either be a String provided by the user, which MUST be interpreted as the bytes of
      //# UTF-8 Encoding of the String, or a v4 UUID, which SHOULD be interpreted as the 16 byte representation of the UUID.

      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id-1
      //# The constructor of the Hierarchical Keyring MUST record these bytes at construction time.

      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
      //# If provided, it MUST be interpreted as UTF8 bytes.

      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id
      //= type=exception
      //# If the PartitionId is NOT provided by the user, it MUST be set to the 16 byte representation of a v4 UUID.
      partitionId ? stringToUtf8Bytes(partitionId) : randomBytes(64)
    )

    /* Precondition: The branch key id must be a string */
    if (branchKeyId) {
      needs(
        typeof branchKeyId === 'string',
        'The branch key id must be a string'
      )
    } else {
      branchKeyId = undefined
    }

    /* Precondition: The branch key id supplier must be a BranchKeyIdSupplier */
    if (branchKeyIdSupplier) {
      needs(
        isBranchKeyIdSupplier(branchKeyIdSupplier),
        'The branch key id supplier must be a BranchKeyIdSupplier'
      )
    } else {
      branchKeyIdSupplier = undefined
    }

    /* Precondition: The keystore must be a BranchKeyStore */
    needs(
      isIBranchKeyStoreNode(keyStore),
      'The keystore must be a BranchKeyStore'
    )

    readOnlyProperty(
      this,
      '_logicalKeyStoreName',
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#logical-key-store-name
      //# Logical Key Store Name MUST be converted to UTF8 Bytes to be used in
      //# the cache identifiers.
      stringToUtf8Bytes(keyStore.getKeyStoreInfo().logicalKeyStoreName)
    )

    /* Precondition: The cache limit TTL must be a number */
    needs(
      typeof cacheLimitTtl === 'number',
      'The cache limit TTL must be a number'
    )

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
    //# The maximum amount of time in seconds that an entry within the cache may be used before it MUST be evicted.
    //# The client MUST set a time-to-live (TTL) for [branch key materials](../structures.md#branch-key-materials) in the underlying cache.
    //# This value MUST be greater than zero.
    /* Precondition: Cache limit TTL must be non-negative and less than or equal to (Number.MAX_SAFE_INTEGER / 1000) seconds */
    // In the MPL, TTL can be a non-negative signed 64-bit integer.
    // However, JavaScript numbers cannot safely represent integers beyond
    // Number.MAX_SAFE_INTEGER. Thus, we will cap TTL in seconds such that TTL
    // in ms is <= Number.MAX_SAFE_INTEGER. TTL could be a BigInt type but this
    // would require casting back to a number in order to configure the CMC,
    // which leads to a lossy conversion
    needs(
      0 <= cacheLimitTtl && cacheLimitTtl * 1000 <= Number.MAX_SAFE_INTEGER,
      'Cache limit TTL must be non-negative and less than or equal to (Number.MAX_SAFE_INTEGER / 1000) seconds'
    )

    /* Precondition: Must provide a branch key identifier or supplier */
    needs(
      branchKeyId || branchKeyIdSupplier,
      'Must provide a branch key identifier or supplier'
    )

    readOnlyProperty(this, 'keyStore', Object.freeze(keyStore))
    /* Postcondition: The keystore object is frozen */

    // convert seconds to milliseconds
    readOnlyProperty(this, 'cacheLimitTtl', cacheLimitTtl * 1000)

    readOnlyProperty(this, 'branchKeyId', branchKeyId)

    readOnlyProperty(
      this,
      'branchKeyIdSupplier',
      branchKeyIdSupplier
        ? Object.freeze(branchKeyIdSupplier)
        : branchKeyIdSupplier
    )
    /* Postcondition: Provided branch key supplier must be frozen */

    if (cache) {
      needs(!maxCacheSize, 'Max cache size not supported when passing a cache.')
    } else {
      /* Precondition: The max cache size must be a number */
      needs(
        // Order is important, 0 is a number but also false.
        typeof maxCacheSize === 'number' || !maxCacheSize,
        'The max cache size must be a number'
      )

      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
      //# If no max cache size is provided, the cryptographic materials cache MUST be configured to a
      //# max cache size of 1000.
      maxCacheSize = maxCacheSize === 0 || maxCacheSize ? maxCacheSize : 1000
      /* Precondition: Max cache size must be non-negative and less than or equal Number.MAX_SAFE_INTEGER */
      needs(
        0 <= maxCacheSize && maxCacheSize <= Number.MAX_SAFE_INTEGER,
        'Max cache size must be non-negative and less than or equal Number.MAX_SAFE_INTEGER'
      )

      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
      //# On initialization the Hierarchical Keyring MUST initialize a [cryptographic-materials-cache](../local-cryptographic-materials-cache.md) with the configured cache limit TTL and the max cache size.

      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
      //# If the Hierarchical Keyring does NOT get a `Shared` cache on initialization,
      //# it MUST initialize a [cryptographic-materials-cache](../local-cryptographic-materials-cache.md)
      //# with the user provided cache limit TTL and the entry capacity.
      cache = getLocalCryptographicMaterialsCache(maxCacheSize)
    }
    readOnlyProperty(this, 'maxCacheSize', maxCacheSize)
    readOnlyProperty(this, '_cmc', cache)

    Object.freeze(this)
    /* Postcondition: The HKR object must be frozen */
  }

  async _onEncrypt(
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //= type=implication
    //# OnEncrypt MUST take [encryption materials](../structures.md#encryption-materials) as input.
    encryptionMaterial: NodeEncryptionMaterial
  ): Promise<NodeEncryptionMaterial> {
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# The `branchKeyId` used in this operation is either the configured branchKeyId, if supplied, or the result of the `branchKeySupplier`'s
    //# `getBranchKeyId` operation, using the encryption material's encryption context as input.
    const branchKeyId = getBranchKeyId(this, encryptionMaterial)

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# The hierarchical keyring MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
    //# to compute the [cache entry identifier](../cryptographic-materials-cache.md#cache-identifier).
    const cacheEntryId = getCacheEntryId(
      this._logicalKeyStoreName,
      this._partition,
      branchKeyId
    )

    const branchKeyMaterials = await getBranchKeyMaterials(
      this,
      this._cmc,
      branchKeyId,
      cacheEntryId
    )

    // get a pdk (generate it if not already set)
    const pdk = getPlaintextDataKey(encryptionMaterial)

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# If the keyring is unable to wrap a plaintext data key, OnEncrypt MUST fail
    //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# - MUST wrap a data key with the branch key materials according to the [branch key wrapping](#branch-key-wrapping) section.
    const edk = wrapPlaintextDataKey(
      pdk,
      branchKeyMaterials,
      encryptionMaterial
    )

    // return the modified encryption material with the new edk and newly
    // generated pdk (if applicable)
    return modifyEncryptionMaterial(encryptionMaterial, pdk, edk, branchKeyId)
  }

  async onDecrypt(
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //= type=implication
    //# OnDecrypt MUST take [decryption materials](../structures.md#decryption-materials) and a list of [encrypted data keys](../structures.md#encrypted-data-keys) as input.
    material: NodeDecryptionMaterial,
    encryptedDataKeys: EncryptedDataKey[]
  ): Promise<DecryptionMaterial<NodeAlgorithmSuite>> {
    needs(isDecryptionMaterial(material), 'Unsupported material type.')

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //# If the decryption materials already contain a `PlainTextDataKey`, OnDecrypt MUST fail.
    /* Precondition: If the decryption materials already contain a PlainTextDataKey, OnDecrypt MUST fail */
    needs(
      !material.hasUnencryptedDataKey,
      'Decryption materials already contain a plaintext data key'
    )

    needs(
      encryptedDataKeys.every((edk) => edk instanceof EncryptedDataKey),
      'Unsupported EncryptedDataKey type'
    )

    const _material = await this._onDecrypt(material, encryptedDataKeys)

    needs(
      material === _material,
      'New DecryptionMaterial instances can not be created.'
    )

    return material
  }

  cacheEntryHasExceededLimits({ now }: BranchKeyMaterialEntry): boolean {
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
    //# `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
    //# valid for TTL of the Hierarchical Keyring getting the cache entry.

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //# There MUST be a check (cacheEntryWithinLimits) to make sure that for the cache entry found, who's TTL has NOT expired,
    //# `time.now() - cacheEntryCreationTime <= ttlSeconds` is true and
    //# valid for TTL of the Hierarchical Keyring getting the cache entry.

    const age = Date.now() - now
    return age > this.cacheLimitTtl
  }

  async _onDecrypt(
    decryptionMaterial: NodeDecryptionMaterial,
    encryptedDataKeyObjs: EncryptedDataKey[]
  ): Promise<NodeDecryptionMaterial> {
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //# The `branchKeyId` used in this operation is either the configured branchKeyId, if supplied, or the result of the `branchKeySupplier`'s
    //# `getBranchKeyId` operation, using the decryption material's encryption context as input.
    const branchKeyId = getBranchKeyId(this, decryptionMaterial)

    // filter out edk objects that don't match this keyring's configuration
    const filteredEdkObjs = encryptedDataKeyObjs.filter((edkObj) =>
      filterEdk(branchKeyId, edkObj)
    )

    /* Precondition: There must be an encrypted data key that matches this keyring configuration */
    needs(
      filteredEdkObjs.length > 0,
      "There must be an encrypted data key that matches this keyring's configuration"
    )

    const errors: Catchable[] = []
    for (const { encryptedDataKey: ciphertext } of filteredEdkObjs) {
      let udk: Uint8Array | undefined = undefined
      try {
        //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
        //# - Deserialize the UUID string representation of the `version` from the [encrypted data key](../structures.md#encrypted-data-key) [ciphertext](#ciphertext).
        // get the branch key version (as compressed bytes) from the
        // destructured ciphertext of the edk
        const { branchKeyVersionAsBytesCompressed } = destructureCiphertext(
          ciphertext,
          decryptionMaterial.suite
        )

        //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
        //# - The deserialized UUID string representation of the `version`
        // uncompress the branch key version into regular utf8 bytes
        const branchKeyVersionAsBytes = stringToUtf8Bytes(
          decompressBytesToUuidv4(branchKeyVersionAsBytesCompressed)
        )

        //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# The hierarchical keyring MUST use the OnDecrypt formula specified in [Appendix A](#decryption-materials)
        //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
        const cacheEntryId = getCacheEntryId(
          this._logicalKeyStoreName,
          this._partition,
          //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
          //# OnDecrypt MUST calculate the following values:
          branchKeyId,
          branchKeyVersionAsBytes
        )

        // get the string representation of the branch key version
        const branchKeyVersionAsString = decompressBytesToUuidv4(
          branchKeyVersionAsBytesCompressed
        )

        //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# To decrypt each encrypted data key in the filtered set, the hierarchical keyring MUST attempt
        //# to find the corresponding [branch key materials](../structures.md#branch-key-materials)
        //# from the underlying [cryptographic materials cache](../local-cryptographic-materials-cache.md).
        const branchKeyMaterials = await getBranchKeyMaterials(
          this,
          this._cmc,
          branchKeyId,
          cacheEntryId,
          branchKeyVersionAsString
        )

        //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# - MUST unwrap the encrypted data key with the branch key materials according to the [branch key unwrapping](#branch-key-unwrapping) section.
        udk = unwrapEncryptedDataKey(
          ciphertext,
          branchKeyMaterials,
          decryptionMaterial
        )
      } catch (e) {
        //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
        //# For each encrypted data key in the filtered set, one at a time, OnDecrypt MUST attempt to decrypt the encrypted data key.
        //# If this attempt results in an error, then these errors MUST be collected.
        errors.push({ errPlus: e })
      }

      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
      //# If a decryption succeeds, this keyring MUST
      //# add the resulting plaintext data key to the decryption materials and return the modified materials.
      if (udk) {
        return modifyDencryptionMaterial(decryptionMaterial, udk, branchKeyId)
      }
    }

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //# If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key),
    //# then it MUST yield an error that includes all the collected errors
    //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
    throw new Error(
      errors.reduce(
        (m, e, i) => `${m} Error #${i + 1} \n ${e.errPlus.stack} \n`,
        'Unable to decrypt data key'
      )
    )
  }
}

immutableClass(KmsHierarchicalKeyRingNode)

// The JS version has not been released with a Storm Tracking CMC

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
//= type=exception
//# If the cache to initialize is a [Storm Tracking Cryptographic Materials Cache](../storm-tracking-cryptographic-materials-cache.md#overview)
//# then the [Grace Period](../storm-tracking-cryptographic-materials-cache.md#grace-period) MUST be less than the [cache limit TTL](#cache-limit-ttl).

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
//= type=exception
//# If no `cache` is provided, a `DefaultCache` MUST be configured with entry capacity of 1000.

// These are not something we can enforce

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#logical-key-store-name
//= type=exception
//# > Note: Users MUST NEVER have two different physical Key Stores with the same Logical Key Store Name.

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#shared-cache-considerations
//= type=exception
//# Any keyring that has access to the `Shared` cache MAY be able to use materials
//# that it MAY or MAY NOT have direct access to.
//#
//# Users MUST make sure that all of Partition ID, Logical Key Store Name of the Key Store for the Hierarchical Keyring
//# and Branch Key ID are set to be the same for two Hierarchical Keyrings if and only they want the keyrings to share
//# cache entries.
