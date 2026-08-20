// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Delegation to the real AWS Encryption SDK for JavaScript (Node.js).
 *
 * Translates the modeled ESDKClientConfig (tagged unions via optional members)
 * into real keyrings / materials managers from the repo's own modules, and
 * drives the one-shot and streaming encrypt/decrypt APIs.
 */

import {
  AwsKmsMrkAwareSymmetricDiscoveryKeyringNode,
  AwsKmsMrkAwareSymmetricKeyringNode,
  BranchKeyStoreNode,
  buildAwsKmsMrkAwareStrictMultiKeyringNode,
  buildClient,
  buildDecrypt,
  buildEncrypt,
  CommitmentPolicy,
  getKmsClient,
  getLocalCryptographicMaterialsCache,
  KeyringNode,
  KmsHierarchicalKeyRingNode,
  KmsKeyringNode,
  MultiKeyringNode,
  NodeCachingMaterialsManager,
  NodeDefaultCryptographicMaterialsManager,
  NodeMaterialsManager,
  RawAesKeyringNode,
  RawAesWrappingSuiteIdentifier,
  RawRsaKeyringNode,
  WrappingSuiteIdentifier,
} from '@aws-crypto/client-node'
import { constants } from 'crypto'
import { Readable } from 'stream'
import { ClientError, ServerError } from './errors'
import {
  AwsKmsDiscoveryKeyringConfig,
  AwsKmsHierarchicalKeyringConfig,
  AwsKmsKeyringConfig,
  AwsKmsMrkDiscoveryKeyringConfig,
  AwsKmsMultiKeyringConfig,
  CachingCmmConfig,
  CmmConfig,
  DiscoveryFilterConfig,
  EncryptionContext,
  EsdkClientConfig,
  fromSuiteId,
  KeyringConfig,
  MultiKeyringConfig,
  RawAesKeyringConfig,
  RawRsaKeyringConfig,
  toSuiteId,
} from './model'

type Client = ReturnType<typeof buildEncrypt> & ReturnType<typeof buildDecrypt>

export interface OperationResult {
  data: Buffer
  encryptionContext?: EncryptionContext
  algorithmSuiteId?: string
}

/* Return the single variant set on a tagged-union map, else reject. */
function oneVariant<T extends object>(
  tagged: T,
  what: string
): [string, NonNullable<T[keyof T]>] {
  const present = Object.entries(tagged).filter(
    ([, value]) => value !== null && value !== undefined
  )
  if (present.length !== 1) {
    const names = present.map(([name]) => name).sort()
    throw new ClientError(
      `exactly one ${what} variant must be set, found ${present.length}: ${names}`
    )
  }
  return present[0]
}

function commitmentPolicy(value: string): CommitmentPolicy {
  const policy = CommitmentPolicy[value as keyof typeof CommitmentPolicy]
  if (!policy) throw new ServerError(`unknown commitment policy: ${value}`)
  return policy
}

/* Region segment of a KMS key ARN; '' (SDK default resolution) otherwise. */
function regionFromKeyId(kmsKeyId: string): string {
  if (!kmsKeyId.startsWith('arn:')) return ''
  return kmsKeyId.split(':')[3] ?? ''
}

function kmsClientForRegion(region: string) {
  const client = getKmsClient(region)
  if (!client) throw new ServerError(`no KMS client for region: ${region}`)
  return client
}

function discoveryFilter(filter?: DiscoveryFilterConfig) {
  if (!filter) return undefined
  return { partition: filter.partition, accountIDs: filter.accountIds }
}

const WRAPPING_SUITE_BY_MODEL_NAME: {
  [name: string]: WrappingSuiteIdentifier
} = {
  ALG_AES128_GCM_IV12_TAG16:
    RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING,
  ALG_AES192_GCM_IV12_TAG16:
    RawAesWrappingSuiteIdentifier.AES192_GCM_IV12_TAG16_NO_PADDING,
  ALG_AES256_GCM_IV12_TAG16:
    RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING,
}

function buildRawAes(config: RawAesKeyringConfig): KeyringNode {
  const wrappingSuite = WRAPPING_SUITE_BY_MODEL_NAME[config.wrappingAlg]
  if (wrappingSuite === undefined) {
    throw new ServerError(
      `unknown AES wrapping algorithm: ${config.wrappingAlg}`
    )
  }
  return new RawAesKeyringNode({
    keyNamespace: config.keyNamespace,
    keyName: config.keyName,
    /* The raw keyring requires key material in an isolated buffer, not a view
     * into the request body. */
    unencryptedMasterKey: new Uint8Array(config.wrappingKey),
    wrappingSuite,
  })
}

/* Modeled PaddingScheme -> node crypto padding + OAEP hash. */
const RSA_PADDING_BY_MODEL_NAME: {
  [name: string]: {
    padding: number
    oaepHash?: 'sha1' | 'sha256' | 'sha384' | 'sha512'
  }
} = {
  PKCS1: { padding: constants.RSA_PKCS1_PADDING },
  OAEP_SHA1_MGF1: {
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha1',
  },
  OAEP_SHA256_MGF1: {
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256',
  },
  OAEP_SHA384_MGF1: {
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha384',
  },
  OAEP_SHA512_MGF1: {
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha512',
  },
}

function buildRawRsa(config: RawRsaKeyringConfig): KeyringNode {
  const scheme = RSA_PADDING_BY_MODEL_NAME[config.paddingScheme]
  if (scheme === undefined) {
    throw new ServerError(`unknown RSA padding scheme: ${config.paddingScheme}`)
  }
  return new RawRsaKeyringNode({
    keyNamespace: config.keyNamespace,
    keyName: config.keyName,
    rsaKey: {
      publicKey: config.publicKey ? Buffer.from(config.publicKey) : undefined,
      privateKey: config.privateKey
        ? Buffer.from(config.privateKey)
        : undefined,
    },
    padding: scheme.padding,
    oaepHash: scheme.oaepHash,
  })
}

function buildKeyring(keyring: KeyringConfig): KeyringNode {
  const [name, config] = oneVariant(keyring, 'keyring')
  switch (name) {
    case 'RawAes':
      return buildRawAes(config as RawAesKeyringConfig)
    case 'RawRsa':
      return buildRawRsa(config as RawRsaKeyringConfig)
    case 'AwsKms': {
      const cfg = config as AwsKmsKeyringConfig
      return new KmsKeyringNode({
        generatorKeyId: cfg.kmsKeyId,
        grantTokens: cfg.grantTokens,
      })
    }
    case 'AwsKmsMrk': {
      const cfg = config as AwsKmsKeyringConfig
      return new AwsKmsMrkAwareSymmetricKeyringNode({
        keyId: cfg.kmsKeyId,
        client: kmsClientForRegion(regionFromKeyId(cfg.kmsKeyId)),
        grantTokens: cfg.grantTokens,
      })
    }
    case 'AwsKmsMultiKeyring': {
      const cfg = config as AwsKmsMultiKeyringConfig
      return new KmsKeyringNode({
        generatorKeyId: cfg.generator,
        keyIds: cfg.kmsKeyIds,
        grantTokens: cfg.grantTokens,
      })
    }
    case 'AwsKmsMrkMultiKeyring': {
      const cfg = config as AwsKmsMultiKeyringConfig
      return buildAwsKmsMrkAwareStrictMultiKeyringNode({
        generatorKeyId: cfg.generator,
        keyIds: cfg.kmsKeyIds,
        grantTokens: cfg.grantTokens,
      })
    }
    case 'AwsKmsDiscovery': {
      const cfg = config as AwsKmsDiscoveryKeyringConfig
      return new KmsKeyringNode({
        discovery: true,
        discoveryFilter: discoveryFilter(cfg.discoveryFilter),
        grantTokens: cfg.grantTokens,
      })
    }
    case 'AwsKmsMrkDiscovery': {
      const cfg = config as AwsKmsMrkDiscoveryKeyringConfig
      return new AwsKmsMrkAwareSymmetricDiscoveryKeyringNode({
        client: kmsClientForRegion(cfg.region),
        discoveryFilter: discoveryFilter(cfg.discoveryFilter),
        grantTokens: cfg.grantTokens,
      })
    }
    case 'AwsKmsHierarchical': {
      const cfg = config as AwsKmsHierarchicalKeyringConfig
      const keyStore = new BranchKeyStoreNode({
        storage: { ddbTableName: cfg.keyStoreTableName },
        logicalKeyStoreName: cfg.logicalKeyStoreName,
        kmsConfiguration: { identifier: cfg.kmsKeyArn },
      })
      return new KmsHierarchicalKeyRingNode({
        branchKeyId: cfg.branchKeyId,
        keyStore,
        cacheLimitTtl: cfg.ttlSeconds,
      })
    }
    case 'Multi': {
      const cfg = config as MultiKeyringConfig
      return new MultiKeyringNode({
        generator: cfg.generator ? buildKeyring(cfg.generator) : undefined,
        children: (cfg.childKeyrings ?? []).map(buildKeyring),
      })
    }
    default:
      throw new ClientError(`unsupported keyring variant: ${name}`)
  }
}

function buildCmm(cmm: CmmConfig): NodeMaterialsManager {
  const [name, config] = oneVariant(cmm, 'cmm')
  switch (name) {
    case 'Default': {
      const cfg = config as { keyring: KeyringConfig }
      return new NodeDefaultCryptographicMaterialsManager(
        buildKeyring(cfg.keyring)
      )
    }
    case 'Caching': {
      const cfg = config as CachingCmmConfig
      return new NodeCachingMaterialsManager({
        backingMaterials: buildCmm(cfg.underlyingCMM),
        cache: getLocalCryptographicMaterialsCache(100),
        maxAge: cfg.cacheLimitTtlSeconds * 1000,
        partition: cfg.partitionId,
        maxBytesEncrypted: cfg.limitBytes,
        maxMessagesEncrypted: cfg.limitMessages,
      })
    }
    case 'RequiredEncryptionContext':
      throw new ClientError(
        'the required encryption context CMM is not implemented by the AWS Encryption SDK for JavaScript'
      )
    default:
      throw new ClientError(`unsupported cmm variant: ${name}`)
  }
}

export class EsdkClientBundle {
  constructor(
    private readonly client: Client,
    private readonly cmm: NodeMaterialsManager
  ) {}

  async encrypt(
    plaintext: Uint8Array,
    encryptionContext?: EncryptionContext,
    algorithmSuiteId?: string,
    frameLength?: number
  ): Promise<OperationResult> {
    const { result } = await this.client.encrypt(this.cmm, plaintext, {
      encryptionContext,
      suiteId: algorithmSuiteId ? toSuiteId(algorithmSuiteId) : undefined,
      frameLength,
    })
    return { data: result }
  }

  async decrypt(
    ciphertext: Uint8Array,
    encryptionContext?: EncryptionContext
  ): Promise<OperationResult> {
    const { plaintext, messageHeader } = await this.client.decrypt(
      this.cmm,
      ciphertext
    )
    verifyReproducedContext(messageHeader.encryptionContext, encryptionContext)
    return {
      data: plaintext,
      encryptionContext: { ...messageHeader.encryptionContext },
      algorithmSuiteId: fromSuiteId(messageHeader.suiteId),
    }
  }

  /* Stream variant: drive the streaming encrypt API and collect the output. */
  async encryptStream(
    plaintext: Uint8Array,
    encryptionContext?: EncryptionContext,
    algorithmSuiteId?: string,
    frameLength?: number,
    plaintextLengthBound?: number
  ): Promise<OperationResult> {
    const stream = this.client.encryptStream(this.cmm, {
      encryptionContext,
      suiteId: algorithmSuiteId ? toSuiteId(algorithmSuiteId) : undefined,
      frameLength,
      /* plaintextLength is the maximum the stream will encrypt: the
       * modeled plaintext length bound. */
      plaintextLength: plaintextLengthBound,
    })
    const ciphertext = await collect(Readable.from([plaintext]).pipe(stream))
    return { data: ciphertext }
  }

  /* Stream variant: drive the streaming decrypt API and collect the output. */
  async decryptStream(
    ciphertext: Uint8Array,
    encryptionContext?: EncryptionContext
  ): Promise<OperationResult> {
    const stream = this.client.decryptStream(this.cmm)
    let header:
      | { encryptionContext: EncryptionContext; suiteId: number }
      | undefined
    stream.once('MessageHeader', (messageHeader) => {
      header = messageHeader
    })
    const plaintext = await collect(Readable.from([ciphertext]).pipe(stream))
    if (!header) throw new ClientError('no message header in ciphertext')
    verifyReproducedContext(header.encryptionContext, encryptionContext)
    return {
      data: plaintext,
      encryptionContext: { ...header.encryptionContext },
      algorithmSuiteId: fromSuiteId(header.suiteId),
    }
  }
}

/* The decryptor authenticated the message's encryption context; every
 * reproduced pair the caller supplied must be present in it. */
function verifyReproducedContext(
  messageContext: Readonly<EncryptionContext>,
  reproduced?: EncryptionContext
): void {
  if (!reproduced) return
  for (const [key, value] of Object.entries(reproduced)) {
    if (messageContext[key] !== value) {
      throw new ClientError(
        `reproduced encryption context does not match the message: key ${key}`
      )
    }
  }
}

async function collect(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  return Buffer.concat(chunks)
}

export function buildClientBundle(config: EsdkClientConfig): EsdkClientBundle {
  const policy = commitmentPolicy(config.commitmentPolicy)
  const cmm = buildCmm(config.cmm)
  const client = buildClient({
    commitmentPolicy: policy,
    maxEncryptedDataKeys:
      config.maxEncryptedDataKeys === undefined ||
      config.maxEncryptedDataKeys === null
        ? false
        : config.maxEncryptedDataKeys,
  })
  return new EsdkClientBundle(client, cmm)
}
