// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Protocol tests over real HTTP on a local port, no AWS credentials: raw-AES
 * round trips through Encrypt/Decrypt and EncryptStream/DecryptStream, header
 * validation, unknown-operation and unknown-client rejection, and the modeled
 * error discriminators.
 */

import { expect } from 'chai'
import * as http from 'http'
import { AddressInfo } from 'net'
import { CborValue, decode, encode } from '../src/cbor'
import { createServer } from '../src/server'

const GENERIC_SERVER_ERROR =
  'aws.cryptography.esdk.testserver#GenericServerError'
const ESDK_CLIENT_ERROR = 'aws.cryptography.esdk.testserver#ESDKClientError'

interface Response {
  status: number
  body: { [key: string]: CborValue }
}

let server: http.Server
let port: number

before((done) => {
  server = createServer()
  server.listen(0, '127.0.0.1', () => {
    port = (server.address() as AddressInfo).port
    done()
  })
})

after((done) => {
  server.close(() => done())
})

function post(
  path: string,
  payload: CborValue,
  headers?: { [name: string]: string }
): Promise<Response> {
  const body = encode(payload)
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path,
        headers: headers ?? {
          'smithy-protocol': 'rpc-v2-cbor',
          'content-type': 'application/cbor',
          'content-length': body.length,
        },
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => chunks.push(chunk))
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            body: decode(Buffer.concat(chunks)) as Response['body'],
          })
        })
      }
    )
    req.on('error', reject)
    req.end(body)
  })
}

function operation(name: string, payload: CborValue): Promise<Response> {
  return post(`/service/ESDKTestServer/operation/${name}`, payload)
}

function rawAesConfig(): CborValue {
  return {
    commitmentPolicy: 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
    cmm: {
      Default: {
        keyring: {
          RawAes: {
            keyNamespace: 'esdk-test-server',
            keyName: 'raw-aes-round-trip-key',
            wrappingKey: Buffer.from(Array.from({ length: 32 }, (_, i) => i)),
            wrappingAlg: 'ALG_AES256_GCM_IV12_TAG16',
          },
        },
      },
    },
  }
}

async function createClient(config: CborValue): Promise<string> {
  const res = await operation('CreateClient', { config })
  expect(res.status).to.equal(200)
  const clientId = res.body.clientId
  expect(clientId).to.be.a('string').and.not.empty
  return clientId as string
}

const PLAINTEXT = Buffer.from('esdk-test-server round trip plaintext')
const CONTEXT = { purpose: 'test', origin: 'protocol-suite' }

describe('raw-AES round trip', () => {
  it('Encrypt then Decrypt recovers the plaintext, context, and suite', async () => {
    const clientId = await createClient(rawAesConfig())

    const encrypted = await operation('Encrypt', {
      clientId,
      plaintext: PLAINTEXT,
      encryptionContext: CONTEXT,
    })
    expect(encrypted.status).to.equal(200)
    const ciphertext = encrypted.body.ciphertext as Uint8Array
    expect(ciphertext).to.be.instanceOf(Uint8Array)
    expect(Buffer.from(ciphertext).includes(PLAINTEXT)).to.equal(false)

    const decrypted = await operation('Decrypt', {
      clientId,
      ciphertext,
      encryptionContext: CONTEXT,
    })
    expect(decrypted.status).to.equal(200)
    expect(Buffer.from(decrypted.body.plaintext as Uint8Array)).to.deep.equal(
      PLAINTEXT
    )
    expect(decrypted.body.encryptionContext).to.deep.include(CONTEXT)
    /* The library default under REQUIRE_ENCRYPT_REQUIRE_DECRYPT is the
     * committing + signing suite. */
    expect(decrypted.body.algorithmSuiteId).to.equal(
      'ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384'
    )
  })

  it('honors an explicit algorithm suite and frame length', async () => {
    const clientId = await createClient({
      ...(rawAesConfig() as object),
      commitmentPolicy: 'FORBID_ENCRYPT_ALLOW_DECRYPT',
    } as CborValue)

    const encrypted = await operation('Encrypt', {
      clientId,
      plaintext: PLAINTEXT,
      algorithmSuiteId: 'ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256',
      frameLength: 16,
    })
    expect(encrypted.status).to.equal(200)

    const decrypted = await operation('Decrypt', {
      clientId,
      ciphertext: encrypted.body.ciphertext,
    })
    expect(decrypted.status).to.equal(200)
    expect(Buffer.from(decrypted.body.plaintext as Uint8Array)).to.deep.equal(
      PLAINTEXT
    )
    expect(decrypted.body.algorithmSuiteId).to.equal(
      'ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256'
    )
  })

  it('rejects a mismatched reproduced encryption context as ESDKClientError', async () => {
    const clientId = await createClient(rawAesConfig())
    const encrypted = await operation('Encrypt', {
      clientId,
      plaintext: PLAINTEXT,
      encryptionContext: CONTEXT,
    })
    const decrypted = await operation('Decrypt', {
      clientId,
      ciphertext: encrypted.body.ciphertext,
      encryptionContext: { ...CONTEXT, purpose: 'tampered' },
    })
    expect(decrypted.status).to.equal(400)
    expect(decrypted.body.__type).to.equal(ESDK_CLIENT_ERROR)
  })

  it('rejects a tampered message header as ESDKClientError', async () => {
    const clientId = await createClient(rawAesConfig())
    const encrypted = await operation('Encrypt', {
      clientId,
      plaintext: PLAINTEXT,
    })
    const tampered = Buffer.from(encrypted.body.ciphertext as Uint8Array)
    tampered[3] ^= 0xff

    const decrypted = await operation('Decrypt', {
      clientId,
      ciphertext: tampered,
    })
    expect(decrypted.status).to.equal(400)
    expect(decrypted.body.__type).to.equal(ESDK_CLIENT_ERROR)
    expect(decrypted.body.message).to.be.a('string').and.not.empty
  })
})

describe('streaming round trip', () => {
  it('EncryptStream then DecryptStream recovers the plaintext', async () => {
    const clientId = await createClient(rawAesConfig())

    const encrypted = await operation('EncryptStream', {
      clientId,
      plaintext: PLAINTEXT,
      encryptionContext: CONTEXT,
      frameLength: 16,
    })
    expect(encrypted.status).to.equal(200)

    const decrypted = await operation('DecryptStream', {
      clientId,
      ciphertext: encrypted.body.ciphertext,
      encryptionContext: CONTEXT,
    })
    expect(decrypted.status).to.equal(200)
    expect(Buffer.from(decrypted.body.plaintext as Uint8Array)).to.deep.equal(
      PLAINTEXT
    )
    expect(decrypted.body.encryptionContext).to.deep.include(CONTEXT)
  })

  it('blob and stream variants interoperate', async () => {
    const clientId = await createClient(rawAesConfig())
    const encrypted = await operation('Encrypt', {
      clientId,
      plaintext: PLAINTEXT,
    })
    const decrypted = await operation('DecryptStream', {
      clientId,
      ciphertext: encrypted.body.ciphertext,
    })
    expect(decrypted.status).to.equal(200)
    expect(Buffer.from(decrypted.body.plaintext as Uint8Array)).to.deep.equal(
      PLAINTEXT
    )
  })

  it('rejects a plaintext exceeding plaintextLengthBound as ESDKClientError', async () => {
    const clientId = await createClient(rawAesConfig())
    const res = await operation('EncryptStream', {
      clientId,
      plaintext: PLAINTEXT,
      plaintextLengthBound: 8,
    })
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(ESDK_CLIENT_ERROR)
  })
})

describe('wire contract', () => {
  it('rejects a missing smithy-protocol header as GenericServerError', async () => {
    const res = await post(
      '/service/ESDKTestServer/operation/CreateClient',
      { config: rawAesConfig() },
      { 'content-type': 'application/cbor' }
    )
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(GENERIC_SERVER_ERROR)
    expect(res.body.message).to.contain('smithy-protocol')
  })

  it('rejects a wrong content-type as GenericServerError', async () => {
    const res = await post(
      '/service/ESDKTestServer/operation/CreateClient',
      { config: rawAesConfig() },
      { 'smithy-protocol': 'rpc-v2-cbor', 'content-type': 'application/json' }
    )
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(GENERIC_SERVER_ERROR)
    expect(res.body.message).to.contain('content-type')
  })

  it('rejects an unknown operation as GenericServerError', async () => {
    const res = await operation('Reticulate', {})
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(GENERIC_SERVER_ERROR)
    expect(res.body.message).to.contain('unknown operation')
  })

  it('rejects an unknown clientId as GenericServerError', async () => {
    const res = await operation('Encrypt', {
      clientId: 'no-such-client',
      plaintext: PLAINTEXT,
    })
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(GENERIC_SERVER_ERROR)
    expect(res.body.message).to.contain('no client registered')
  })

  it('rejects undecodable CBOR as GenericServerError', async () => {
    const res = await new Promise<Response>((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          method: 'POST',
          path: '/service/ESDKTestServer/operation/CreateClient',
          headers: {
            'smithy-protocol': 'rpc-v2-cbor',
            'content-type': 'application/cbor',
          },
        },
        (response) => {
          const chunks: Buffer[] = []
          response.on('data', (chunk: Buffer) => chunks.push(chunk))
          response.on('end', () =>
            resolve({
              status: response.statusCode ?? 0,
              body: decode(Buffer.concat(chunks)) as Response['body'],
            })
          )
        }
      )
      req.on('error', reject)
      req.end(Buffer.from([0xff, 0xff]))
    })
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(GENERIC_SERVER_ERROR)
    expect(res.body.message).to.contain('decode')
  })
})

describe('client construction', () => {
  it('rejects a config with two keyring variants as ESDKClientError', async () => {
    const config = rawAesConfig() as {
      cmm: { Default: { keyring: { [name: string]: CborValue } } }
    }
    config.cmm.Default.keyring.AwsKms = { kmsKeyId: 'alias/unused' }
    const res = await operation('CreateClient', { config })
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(ESDK_CLIENT_ERROR)
    expect(res.body.message).to.contain('exactly one keyring variant')
  })

  it('rejects the unsupported AwsKmsRsa keyring as ESDKClientError', async () => {
    const res = await operation('CreateClient', {
      config: {
        commitmentPolicy: 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
        cmm: {
          Default: {
            keyring: {
              AwsKmsRsa: { kmsKeyId: 'alias/unused' },
            },
          },
        },
      },
    })
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(ESDK_CLIENT_ERROR)
    expect(res.body.message).to.contain('unsupported keyring variant')
  })

  it('rejects the unsupported RequiredEncryptionContext CMM as ESDKClientError', async () => {
    const res = await operation('CreateClient', {
      config: {
        commitmentPolicy: 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
        cmm: {
          RequiredEncryptionContext: {
            underlyingCMM: { Default: { keyring: {} } },
            requiredEncryptionContextKeys: ['purpose'],
          },
        },
      },
    })
    expect(res.status).to.equal(400)
    expect(res.body.__type).to.equal(ESDK_CLIENT_ERROR)
    expect(res.body.message).to.contain('required encryption context')
  })

  it('caching CMM round-trips over a raw-AES keyring', async () => {
    const base = rawAesConfig() as { cmm: CborValue; commitmentPolicy: string }
    const clientId = await createClient({
      commitmentPolicy: base.commitmentPolicy,
      cmm: {
        Caching: {
          underlyingCMM: base.cmm,
          cacheLimitTtlSeconds: 60,
        },
      },
    })
    const encrypted = await operation('Encrypt', {
      clientId,
      plaintext: PLAINTEXT,
    })
    expect(encrypted.status).to.equal(200)
    const decrypted = await operation('Decrypt', {
      clientId,
      ciphertext: encrypted.body.ciphertext,
    })
    expect(decrypted.status).to.equal(200)
    expect(Buffer.from(decrypted.body.plaintext as Uint8Array)).to.deep.equal(
      PLAINTEXT
    )
  })

  it('multi-keyring with a raw-AES generator round-trips', async () => {
    const clientId = await createClient({
      commitmentPolicy: 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
      cmm: {
        Default: {
          keyring: {
            Multi: {
              generator: {
                RawAes: {
                  keyNamespace: 'esdk-test-server',
                  keyName: 'generator-key',
                  wrappingKey: Buffer.alloc(32, 1),
                  wrappingAlg: 'ALG_AES256_GCM_IV12_TAG16',
                },
              },
              childKeyrings: [
                {
                  RawAes: {
                    keyNamespace: 'esdk-test-server',
                    keyName: 'child-key',
                    wrappingKey: Buffer.alloc(32, 2),
                    wrappingAlg: 'ALG_AES256_GCM_IV12_TAG16',
                  },
                },
              ],
            },
          },
        },
      },
    })
    const encrypted = await operation('Encrypt', {
      clientId,
      plaintext: PLAINTEXT,
    })
    expect(encrypted.status).to.equal(200)
    const decrypted = await operation('Decrypt', {
      clientId,
      ciphertext: encrypted.body.ciphertext,
    })
    expect(decrypted.status).to.equal(200)
    expect(Buffer.from(decrypted.body.plaintext as Uint8Array)).to.deep.equal(
      PLAINTEXT
    )
  })
})
