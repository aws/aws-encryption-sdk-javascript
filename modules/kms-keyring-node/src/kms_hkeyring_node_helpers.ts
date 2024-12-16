// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  EncryptedDataKey,
  NodeEncryptionMaterial,
  unwrapDataKey,
  NodeAlgorithmSuite,
  NodeDecryptionMaterial,
  NodeBranchKeyMaterial,
  KeyringTraceFlag,
  needs,
  EncryptionContext,
} from '@aws-crypto/material-management'
import { IKmsHierarchicalKeyRingNode } from './kms_hkeyring_node'
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'crypto'
// import { uInt32BE } from '@aws-crypto/serialize'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'
import { kdfCounterMode } from '@aws-crypto/kdf-ctr-mode-node'
import {
  // ACTIVE_AS_BYTES,
  CACHE_ENTRY_ID_DIGEST_ALGORITHM,
  // CACHE_ENTRY_ID_LENGTH,
  CIPHERTEXT_STRUCTURE,
  DECRYPT_FLAGS,
  DERIVED_BRANCH_KEY_LENGTH,
  ENCRYPT_FLAGS,
  KDF_DIGEST_ALGORITHM_SHA_256,
  KEY_DERIVATION_LABEL,
  PROVIDER_ID_HIERARCHY,
  PROVIDER_ID_HIERARCHY_AS_BYTES,
} from './constants'
import { BranchKeyIdSupplier } from '@aws-crypto/kms-keyring'
import { serializeFactory, uuidv4Factory } from '@aws-crypto/serialize'

export const stringToUtf8Bytes = (input: string): Buffer =>
  Buffer.from(input, 'utf-8')
export const utf8BytesToString = (input: Buffer): string =>
  input.toString('utf-8')
const stringToHexBytes = (input: string): Uint8Array =>
  new Uint8Array(Buffer.from(input, 'hex'))
const hexBytesToString = (input: Uint8Array): string =>
  Buffer.from(input).toString('hex')
export const { uuidv4ToCompressedBytes, decompressBytesToUuidv4 } =
  uuidv4Factory(stringToHexBytes, hexBytesToString)
export const { serializeEncryptionContext } =
  serializeFactory(stringToUtf8Bytes)
// const stringToAsciiBytes = (input: string): Buffer =>
//   Buffer.from(input, 'ascii')

export function getBranchKeyId(
  { branchKeyId, branchKeyIdSupplier }: IKmsHierarchicalKeyRingNode,
  { encryptionContext }: NodeEncryptionMaterial | NodeDecryptionMaterial
): string {
  // use the branch key id attribute if it was set, otherwise use the branch key
  // id supplier. The constructor ensures that either the branch key id or
  // supplier is supplied to the keyring
  return (
    branchKeyId ||
    (branchKeyIdSupplier as BranchKeyIdSupplier).getBranchKeyId(
      encryptionContext
    )
  )
}

const RESOURCE_ID = new Uint8Array([0x02])
const NULL_BYTE = new Uint8Array([0x00])
const DECRYPTION_SCOPE = new Uint8Array([0x02])
const ENCRYPTION_SCOPE = new Uint8Array([0x01])

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas
//# When accessing the underlying cryptographic materials cache,
//# the hierarchical keyring MUST use the formulas specified in this appendix
//# in order to compute the [cache entry identifier](../cryptographic-materials-cache.md#cache-identifier).
export function getCacheEntryId(
  logicalKeyStoreName: Buffer,
  partitionId: Buffer,
  branchKeyId: string,
  versionAsBytes?: Buffer
): string {
  // get branch key id as a byte array
  const branchKeyIdAsBytes = stringToUtf8Bytes(branchKeyId)

  let entryInfo
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#resource-suffix
  //# The aforementioned 4 definitions ([Resource Identifier](#resource-identifier),
  //# [Scope Identifier](#scope-identifier), [Partition ID](#partition-id-1), and
  //# [Resource Suffix](#resource-suffix)) MUST be appended together with the null byte, 0x00,
  //# and the SHA384 of the result should be taken as the final cache identifier.

  if (versionAsBytes) {
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //# When the hierarchical keyring receives an OnDecrypt request,
    //# it MUST calculate the cache entry identifier as the
    //# SHA-384 hash of the following byte strings, in the order listed:

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
    //# All the above fields must be separated by a single NULL_BYTE `0x00`.
    //#
    //# | Field                  | Length (bytes) | Interpreted as      |
    //# | ---------------------- | -------------- | ------------------- |
    //# | Resource ID            | 1              | bytes               |
    //# | Null Byte              | 1              | `0x00`              |
    //# | Scope ID               | 1              | bytes               |
    //# | Null Byte              | 1              | `0x00`              |
    //# | Partition ID           | Variable       | bytes               |
    //# | Null Byte              | 1              | `0x00`              |
    //# | Logical Key Store Name | Variable       | UTF-8 Encoded Bytes |
    //# | Null Byte              | 1              | `0x00`              |
    //# | Branch Key ID          | Variable       | UTF-8 Encoded Bytes |
    //# | Null Byte              | 1              | `0x00`              |
    //# | branch-key-version     | 36             | UTF-8 Encoded Bytes |

    entryInfo = Buffer.concat([
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
      //# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
      RESOURCE_ID,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
      //# - MUST be the Scope ID for Decrypt (0x02)
      DECRYPTION_SCOPE,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
      //# - MUST be the Partition ID for the Hierarchical Keyring
      partitionId,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
      //# - MUST be the UTF8 encoded Logical Key Store Name of the keystore for the Hierarchical Keyring
      logicalKeyStoreName,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
      //# - MUST be the UTF8 encoded branch-key-id
      branchKeyIdAsBytes,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#decryption-materials
      //# - MUST be the UTF8 encoded branch-key-version
      versionAsBytes,
    ])
  } else {
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //# When the hierarchical keyring receives an OnEncrypt request,
    //# the cache entry identifier MUST be calculated as the
    //# SHA-384 hash of the following byte strings, in the order listed:

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
    //# All the above fields must be separated by a single NULL_BYTE `0x00`.
    //#
    //# | Field                  | Length (bytes) | Interpreted as      |
    //# | ---------------------- | -------------- | ------------------- |
    //# | Resource ID            | 1              | bytes               |
    //# | Null Byte              | 1              | `0x00`              |
    //# | Scope ID               | 1              | bytes               |
    //# | Null Byte              | 1              | `0x00`              |
    //# | Partition ID           | Variable       | bytes               |
    //# | Null Byte              | 1              | `0x00`              |
    //# | Logical Key Store Name | Variable       | UTF-8 Encoded Bytes |
    //# | Null Byte              | 1              | `0x00`              |
    //# | Branch Key ID          | Variable       | UTF-8 Encoded Bytes |

    entryInfo = Buffer.concat([
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
      //# - MUST be the Resource ID for the Hierarchical Keyring (0x02)
      RESOURCE_ID,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
      //# - MUST be the Scope ID for Encrypt (0x01)
      ENCRYPTION_SCOPE,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
      //# - MUST be the Partition ID for the Hierarchical Keyring
      partitionId,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
      //# - MUST be the UTF8 encoded Logical Key Store Name of the keystore for the Hierarchical Keyring
      logicalKeyStoreName,
      NULL_BYTE,
      //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials
      //# - MUST be the UTF8 encoded branch-key-id
      branchKeyIdAsBytes,
    ])
  }

  // const entryInfo = versionAsBytes
  //   ? Buffer.concat([
  //       RESOURCE_ID,
  //       NULL_BYTE,
  //       DECRYPTION_SCOPE,
  //       NULL_BYTE,
  //       partitionId,
  //       NULL_BYTE,
  //       logicalKeyStoreName,
  //       NULL_BYTE,
  //       branchKeyIdAsBytes,
  //       NULL_BYTE,
  //       versionAsBytes,
  //     ])
  //   : Buffer.concat([
  //       RESOURCE_ID,
  //       NULL_BYTE,
  //       ENCRYPTION_SCOPE,
  //       NULL_BYTE,
  //       partitionId,
  //       NULL_BYTE,
  //       logicalKeyStoreName,
  //       NULL_BYTE,
  //       branchKeyIdAsBytes,
  //     ])

  // encrypt the branch key id buffer with sha512
  return createHash(CACHE_ENTRY_ID_DIGEST_ALGORITHM)
    .update(entryInfo)
    .digest()
    .toString()
}

export async function getBranchKeyMaterials(
  hKeyring: IKmsHierarchicalKeyRingNode,
  cmc: CryptographicMaterialsCache<NodeAlgorithmSuite>,
  branchKeyId: string,
  cacheEntryId: string,
  branchKeyVersion?: string
): Promise<NodeBranchKeyMaterial> {
  const { keyStore, cacheLimitTtl } = hKeyring

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //# The hierarchical keyring MUST attempt to find [branch key materials](../structures.md#branch-key-materials)
  //# from the underlying [cryptographic materials cache](../local-cryptographic-materials-cache.md).
  const cacheEntry = cmc.getBranchKeyMaterial(cacheEntryId)
  let branchKeyMaterials: NodeBranchKeyMaterial
  // if the cache entry is false, branch key materials were not found
  if (!cacheEntry || hKeyring.cacheEntryHasExceededLimits(cacheEntry)) {
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# If this is NOT true, then we MUST treat the cache entry as expired.

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //# If this is NOT true, then we MUST treat the cache entry as expired.

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# If a cache entry is not found or the cache entry is expired, the hierarchical keyring MUST attempt to obtain the branch key materials
    //# by querying the backing branch keystore specified in the [retrieve OnEncrypt branch key materials](#query-branch-keystore-onencrypt) section.
    //# If the keyring is not able to retrieve [branch key materials](../structures.md#branch-key-materials)
    //# through the underlying cryptographic materials cache or
    //# it no longer has access to them through the backing keystore, OnEncrypt MUST fail.

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
    //# Otherwise, OnEncrypt MUST fail.

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
    //# Otherwise, OnDecrypt MUST fail.

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
    //# OnEncrypt MUST call the Keystore's [GetActiveBranchKey](../branch-key-store.md#getactivebranchkey) operation with the following inputs:

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
    //# OnDecrypt MUST call the Keystore's [GetBranchKeyVersion](../branch-key-store.md#getbranchkeyversion) operation with the following inputs:
    branchKeyMaterials = branchKeyVersion
      ? await keyStore.getBranchKeyVersion(branchKeyId, branchKeyVersion)
      : //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
        //# OnEncrypt MUST call the Keystore's [GetActiveBranchKey](../branch-key-store.md#getactivebranchkey) operation with the following inputs:
        await keyStore.getActiveBranchKey(branchKeyId)

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
    //# If the Keystore's GetActiveBranchKey operation succeeds
    //# the keyring MUST put the returned branch key materials in the cache using the
    //# formula defined in [Appendix A](#appendix-a-cache-entry-identifier-formulas).

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
    //# If the Keystore's GetBranchKeyVersion operation succeeds
    //# the keyring MUST put the returned branch key materials in the cache using the
    //# formula defined in [Appendix A](#appendix-a-cache-entry-identifier-formulas).
    cmc.putBranchKeyMaterial(cacheEntryId, branchKeyMaterials, cacheLimitTtl)
  } else {
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //# If a cache entry is found and the entry's TTL has not expired, the hierarchical keyring MUST use those branch key materials for key unwrapping.

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# If a cache entry is found and the entry's TTL has not expired, the hierarchical keyring MUST use those branch key materials for key wrapping.
    branchKeyMaterials = cacheEntry.response
  }

  return branchKeyMaterials
}

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
//# If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key,
//# OnEncrypt MUST generate a random plaintext data key, according to the key length defined in the [algorithm suite](../algorithm-suites.md#encryption-key-length).
//# The process used to generate this random plaintext data key MUST use a secure source of randomness.
export function getPlaintextDataKey(material: NodeEncryptionMaterial) {
  // get the pdk from the encryption material whether it is already set or we
  // must randomly generate it
  return new Uint8Array(
    material.hasUnencryptedDataKey
      ? unwrapDataKey(material.getUnencryptedDataKey())
      : randomBytes(material.suite.keyLengthBytes)
  )
}

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
//# To derive and encrypt a data key the keyring will follow the same key derivation and encryption as [AWS KMS](https://rwc.iacr.org/2018/Slides/Gueron.pdf).
//# The hierarchical keyring MUST:
//# 1. Generate a 16 byte random `salt` using a secure source of randomness
//# 1. Generate a 12 byte random `IV` using a secure source of randomness
//# 1. Use a [KDF in Counter Mode with a Pseudo Random Function with HMAC SHA 256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf) to derive a 32 byte `derivedBranchKey` data key with the following inputs:
//#    - Use the `salt` as the salt.
//#    - Use the branch key as the `key`.
//#    - Use the UTF8 Encoded value "aws-kms-hierarchy" as the label.
//# 1. Encrypt a plaintext data key with the `derivedBranchKey` using `AES-GCM-256` with the following inputs:
//#    - MUST use the `derivedBranchKey` as the AES-GCM cipher key.
//#    - MUST use the plain text data key that will be wrapped by the `derivedBranchKey` as the AES-GCM message.
//#    - MUST use the derived `IV` as the AES-GCM IV.
//#    - MUST use an authentication tag byte of length 16.
//#    - MUST use the serialized [AAD](#branch-key-wrapping-and-unwrapping-aad) as the AES-GCM AAD.
//# If OnEncrypt fails to do any of the above, OnEncrypt MUST fail.
export function wrapPlaintextDataKey(
  pdk: Uint8Array,
  branchKeyMaterials: NodeBranchKeyMaterial,
  { encryptionContext }: NodeEncryptionMaterial
): Uint8Array {
  // get what we need from branch key material to wrap the pdk
  const branchKey = branchKeyMaterials.branchKey()
  const { branchKeyIdentifier, branchKeyVersion: branchKeyVersionAsBytes } =
    branchKeyMaterials
  // compress the branch key version utf8 bytes
  const branchKeyVersionAsBytesCompressed = Buffer.from(
    uuidv4ToCompressedBytes(utf8BytesToString(branchKeyVersionAsBytes))
  )
  const branchKeyIdAsBytes = stringToUtf8Bytes(branchKeyIdentifier)

  // generate salt and IV
  const salt = randomBytes(CIPHERTEXT_STRUCTURE.saltLength)
  const iv = randomBytes(CIPHERTEXT_STRUCTURE.ivLength)

  // derive a key from the branch key
  const derivedBranchKey = kdfCounterMode({
    digestAlgorithm: KDF_DIGEST_ALGORITHM_SHA_256,
    ikm: branchKey,
    nonce: salt,
    purpose: KEY_DERIVATION_LABEL,
    expectedLength: DERIVED_BRANCH_KEY_LENGTH,
  })

  // set up additional auth data
  const wrappedAad = wrapAad(
    branchKeyIdAsBytes,
    branchKeyVersionAsBytesCompressed,
    encryptionContext
  )

  // encrypt the pdk into an edk
  const cipher = createCipheriv('aes-256-gcm', derivedBranchKey, iv).setAAD(
    wrappedAad
  )
  const edkCiphertext = Buffer.concat([cipher.update(pdk), cipher.final()])
  const authTag = cipher.getAuthTag()

  // wrap the edk into a ciphertext
  const ciphertext = new Uint8Array(
    Buffer.concat([
      salt,
      iv,
      branchKeyVersionAsBytesCompressed,
      edkCiphertext,
      authTag,
    ])
  )
  return ciphertext
}

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad
//# To Encrypt and Decrypt the `wrappedDerivedBranchKey` the keyring MUST include the following values as part of the AAD for
//# the AES Encrypt/Decrypt calls.
//# To construct the AAD, the keyring MUST concatenate the following values
//# 1. "aws-kms-hierarchy" as UTF8 Bytes
//# 1. Value of `branch-key-id` as UTF8 Bytes
//# 1. [version](../structures.md#branch-key-version) as Bytes
//# 1. [encryption context](structures.md#encryption-context-1) from the input
//#    [encryption materials](../structures.md#encryption-materials) according to the [encryption context serialization specification](../structures.md#serialization).
//# | Field               | Length (bytes) | Interpreted as                                       |
//# | ------------------- | -------------- | ---------------------------------------------------- |
//# | "aws-kms-hierarchy" | 17             | UTF-8 Encoded                                        |
//# | branch-key-id       | Variable       | UTF-8 Encoded                                        |
//# | version             | 16             | Bytes                                                |
//# | encryption context  | Variable       | [Encryption Context](../structures.md#serialization) |
//# If the keyring cannot serialize the encryption context, the operation MUST fail.
export function wrapAad(
  branchKeyIdAsBytes: Buffer,
  version: Buffer,
  encryptionContext: EncryptionContext
) {
  /* Precondition: Branch key version must be 16 bytes */
  needs(version.length === 16, 'Branch key version must be 16 bytes')

  /* The AAD section is uInt16BE(length) + AAD
   * see: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
   * However, we  _only_ need the ADD.
   * So, I just slice off the length.
   */
  const aad = Buffer.from(
    serializeEncryptionContext(encryptionContext).slice(2)
  )

  return Buffer.concat([
    PROVIDER_ID_HIERARCHY_AS_BYTES,
    branchKeyIdAsBytes,
    version,
    aad,
  ])
}

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
//# Otherwise, OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key)
//# to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:
//# - [ciphertext](../structures.md#ciphertext): MUST be serialized as the [hierarchical keyring ciphertext](#ciphertext)
//# - [key provider id](../structures.md#key-provider-id): MUST be UTF8 Encoded "aws-kms-hierarchy"
//# - [key provider info](../structures.md#key-provider-information): MUST be the UTF8 Encoded AWS DDB response `branch-key-id`
export function modifyEncryptionMaterial(
  encryptionMaterial: NodeEncryptionMaterial,
  pdk: Uint8Array,
  edk: Uint8Array,
  wrappingKeyName: string
): NodeEncryptionMaterial {
  // if the pdk was already set in the encryption material, we should not reset
  if (!encryptionMaterial.hasUnencryptedDataKey) {
    encryptionMaterial.setUnencryptedDataKey(pdk, {
      keyNamespace: PROVIDER_ID_HIERARCHY,
      keyName: wrappingKeyName,
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
  }

  // add the edk (that we created during onEncrypt) to the encryption material
  return encryptionMaterial.addEncryptedDataKey(
    new EncryptedDataKey({
      providerId: PROVIDER_ID_HIERARCHY,
      providerInfo: wrappingKeyName,
      encryptedDataKey: edk,
    }),
    ENCRYPT_FLAGS
  )
}

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
//# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration. For the encrypted data key to match:
//# - Its provider ID MUST match the UTF8 Encoded value of “aws-kms-hierarchy”.
//# - Deserialize the key provider info, if deserialization fails the next EDK in the set MUST be attempted.
//#   - The deserialized key provider info MUST be UTF8 Decoded and MUST match this keyring's configured `Branch Key Identifier`.
export function filterEdk(
  branchKeyId: string,
  { providerId, providerInfo }: EncryptedDataKey
): boolean {
  // check if the edk matches the keyring's configuration according to provider
  // id and info (the edk object should have been wrapped by the branch key
  // configured in this keyring or decryption material's encryption context)

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
  //# - Deserialize the UTF8-Decoded `branch-key-id` from the [key provider info](../structures.md#key-provider-information) of the [encrypted data key](../structures.md#encrypted-data-key)
  //# and verify this is equal to the configured or supplied `branch-key-id`.
  return providerId === PROVIDER_ID_HIERARCHY
    ? branchKeyId === providerInfo
    : false
}

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ciphertext
//# The following table describes the fields that form the ciphertext for this keyring.
//# The bytes are appended in the order shown.
//# The Encryption Key is variable.
//# It will be whatever length is represented by the algorithm suite.
//# Because all the other values are constant,
//# this variability in the encryption key does not impact the format.
//# | Field              | Length (bytes) | Interpreted as |
//# | ------------------ | -------------- | -------------- |
//# | Salt               | 16             | bytes          |
//# | IV                 | 12             | bytes          |
//# | Version            | 16             | bytes          |
//# | Encrypted Key      | Variable       | bytes          |
//# | Authentication Tag | 16             | bytes          |
export function destructureCiphertext(
  ciphertext: Uint8Array,
  { keyLengthBytes }: NodeAlgorithmSuite
) {
  // what we expect the length of the edk object's ciphertext to be. This
  // depends on the byte key length specified by the algorithm suite
  const expectedCiphertextLength =
    CIPHERTEXT_STRUCTURE.saltLength +
    CIPHERTEXT_STRUCTURE.ivLength +
    CIPHERTEXT_STRUCTURE.branchKeyVersionCompressedLength +
    keyLengthBytes +
    CIPHERTEXT_STRUCTURE.authTagLength
  /* Precondition: The edk ciphertext must have the correct length */
  needs(
    ciphertext.length === expectedCiphertextLength,
    `The encrypted data key ciphertext must be ${expectedCiphertextLength} bytes long`
  )

  let start = 0
  let end = 0

  // extract the salt from the edk ciphertext
  start = end
  end += CIPHERTEXT_STRUCTURE.saltLength
  const salt = Buffer.from(ciphertext.subarray(start, end))

  // extract the IV from the edk ciphertext
  start = end
  end += CIPHERTEXT_STRUCTURE.ivLength
  const iv = Buffer.from(ciphertext.subarray(start, end))

  // extract the compressed branch key version from the edk ciphertext
  start = end
  end += CIPHERTEXT_STRUCTURE.branchKeyVersionCompressedLength
  const branchKeyVersionAsBytesCompressed = Buffer.from(
    ciphertext.subarray(start, end)
  )

  // extract the encrypted data key from the edk ciphertext
  start = end
  end += keyLengthBytes
  const encryptedDataKey = Buffer.from(ciphertext.subarray(start, end))

  // extract the auth tag from the edk ciphertext
  start = end
  end += CIPHERTEXT_STRUCTURE.authTagLength
  const authTag = Buffer.from(ciphertext.subarray(start, end))

  return {
    salt,
    iv,
    branchKeyVersionAsBytesCompressed,
    encryptedDataKey,
    authTag,
  }
}

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-unwrapping
//# To decrypt an encrypted data key with a branch key, the hierarchical keyring MUST:
//# 1. Deserialize the 16 byte random `salt` from the [edk ciphertext](../structures.md#ciphertext).
//# 1. Deserialize the 12 byte random `IV` from the [edk ciphertext](../structures.md#ciphertext).
//# 1. Deserialize the 16 byte `version` from the [edk ciphertext](../structures.md#ciphertext).
//# 1. Deserialize the `encrypted key` from the [edk ciphertext](../structures.md#ciphertext).
//# 1. Deserialize the `authentication tag` from the [edk ciphertext](../structures.md#ciphertext).
//# 1. Use a [KDF in Counter Mode with a Pseudo Random Function with HMAC SHA 256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf) to derive
//#    the 32 byte `derivedBranchKey` data key with the following inputs:
//#    - Use the `salt` as the salt.
//#    - Use the branch key as the `key`.
//# 1. Decrypt the encrypted data key with the `derivedBranchKey` using `AES-GCM-256` with the following inputs:
//#    - It MUST use the `encrypted key` obtained from deserialization as the AES-GCM input ciphertext.
//#    - It MUST use the `authentication tag` obtained from deserialization as the AES-GCM input authentication tag.
//#    - It MUST use the `derivedBranchKey` as the AES-GCM cipher key.
//#    - It MUST use the `IV` obtained from deserialization as the AES-GCM input IV.
//#    - It MUST use the serialized [encryption context](#branch-key-wrapping-and-unwrapping-aad) as the AES-GCM AAD.
//# If OnDecrypt fails to do any of the above, OnDecrypt MUST fail.
export function unwrapEncryptedDataKey(
  ciphertext: Uint8Array,
  branchKeyMaterials: NodeBranchKeyMaterial,
  { encryptionContext, suite }: NodeDecryptionMaterial
) {
  // get what we need from the branch key materials to unwrap the edk
  const branchKey = branchKeyMaterials.branchKey()
  const { branchKeyIdentifier } = branchKeyMaterials
  const branchKeyIdAsBytes = stringToUtf8Bytes(branchKeyIdentifier)

  // get the salt, iv, edk, and auth tag from the edk ciphertext
  const {
    salt,
    iv,
    encryptedDataKey,
    authTag,
    branchKeyVersionAsBytesCompressed,
  } = destructureCiphertext(ciphertext, suite)

  // derive a key from the branch key
  const derivedBranchKey = kdfCounterMode({
    digestAlgorithm: KDF_DIGEST_ALGORITHM_SHA_256,
    ikm: branchKey,
    nonce: salt,
    purpose: KEY_DERIVATION_LABEL,
    expectedLength: DERIVED_BRANCH_KEY_LENGTH,
  })

  // set up additional auth data
  const wrappedAad = wrapAad(
    branchKeyIdAsBytes,
    branchKeyVersionAsBytesCompressed,
    encryptionContext
  )

  // decipher the edk to get the udk/pdk
  const decipher = createDecipheriv('aes-256-gcm', derivedBranchKey, iv)
    .setAAD(wrappedAad)
    .setAuthTag(authTag)
  const udk = Buffer.concat([
    decipher.update(encryptedDataKey),
    decipher.final(),
  ])

  return new Uint8Array(udk)
}

export function modifyDencryptionMaterial(
  decryptionMaterial: NodeDecryptionMaterial,
  udk: Uint8Array,
  wrappingKeyName: string
): NodeDecryptionMaterial {
  // modify the decryption material by setting the plaintext data key
  return decryptionMaterial.setUnencryptedDataKey(udk, {
    keyNamespace: PROVIDER_ID_HIERARCHY,
    keyName: wrappingKeyName,
    flags: DECRYPT_FLAGS,
  })
}
