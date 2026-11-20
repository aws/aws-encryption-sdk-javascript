// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* rpcv2Cbor HTTP wire layer.
 *
 * Routes POST /service/ESDKTestServer/operation/{Operation}, validates the
 * smithy-protocol and content-type headers, decodes the CBOR request body,
 * dispatches to the operation handler, and encodes the CBOR response. Every
 * outcome is a modeled success response, a GenericServerError, or an
 * ESDKClientError — the errors as a CBOR map carrying the __type discriminator.
 */

import * as http from 'http'
import { randomUUID } from 'crypto'
import { buildClientBundle, EsdkClientBundle, OperationResult } from './bridge'
import { CborValue, decode, encode } from './cbor'
import {
  ClientError,
  describeError,
  ESDK_CLIENT_ERROR,
  GENERIC_SERVER_ERROR,
  ServerError,
} from './errors'
import {
  CreateClientRequest,
  DecryptRequest,
  DecryptStreamRequest,
  EncryptRequest,
  EncryptStreamRequest,
} from './model'

const SMITHY_PROTOCOL = 'rpc-v2-cbor'
const CBOR_CONTENT_TYPE = 'application/cbor'
const OPERATION_PATH_PREFIX = '/service/ESDKTestServer/operation/'

class ClientRegistry {
  private readonly clients = new Map<string, EsdkClientBundle>()

  register(bundle: EsdkClientBundle): string {
    const clientId = randomUUID()
    this.clients.set(clientId, bundle)
    return clientId
  }

  resolve(clientId?: string): EsdkClientBundle {
    if (!clientId) {
      throw new ServerError('clientId is required and must be non-empty')
    }
    const bundle = this.clients.get(clientId)
    if (!bundle) {
      throw new ServerError(`no client registered for clientId: ${clientId}`)
    }
    return bundle
  }
}

async function createClient(
  registry: ClientRegistry,
  request: CreateClientRequest
): Promise<CborValue> {
  const config = request.config
  if (!config) throw new ServerError('config is required')
  let bundle: EsdkClientBundle
  try {
    bundle = buildClientBundle(config)
  } catch (err) {
    if (err instanceof ClientError || err instanceof ServerError) throw err
    throw new ServerError(
      `CreateClient failed to construct the ESDK client: ${describeError(err)}`
    )
  }
  return { clientId: registry.register(bundle) }
}

/* Forward an ESDK-thrown failure as ESDKClientError. */
async function delegated(
  operation: Promise<OperationResult>
): Promise<OperationResult> {
  try {
    return await operation
  } catch (err) {
    if (err instanceof ClientError || err instanceof ServerError) throw err
    throw new ClientError(describeError(err))
  }
}

function decryptResponse(result: OperationResult): CborValue {
  const response: { [key: string]: CborValue } = { plaintext: result.data }
  if (
    result.encryptionContext &&
    Object.keys(result.encryptionContext).length > 0
  ) {
    response.encryptionContext = result.encryptionContext
  }
  if (result.algorithmSuiteId) {
    response.algorithmSuiteId = result.algorithmSuiteId
  }
  return response
}

async function dispatch(
  registry: ClientRegistry,
  operation: string,
  request: { [key: string]: CborValue }
): Promise<CborValue> {
  switch (operation) {
    case 'CreateClient':
      return createClient(registry, request as CreateClientRequest)
    case 'Encrypt': {
      const req = request as EncryptRequest
      const bundle = registry.resolve(req.clientId)
      if (!req.plaintext) throw new ServerError('plaintext is required')
      const { data } = await delegated(
        bundle.encrypt(
          req.plaintext,
          req.encryptionContext,
          req.algorithmSuiteId,
          req.frameLength
        )
      )
      return { ciphertext: data }
    }
    case 'Decrypt': {
      const req = request as DecryptRequest
      const bundle = registry.resolve(req.clientId)
      if (!req.ciphertext) throw new ServerError('ciphertext is required')
      return decryptResponse(
        await delegated(bundle.decrypt(req.ciphertext, req.encryptionContext))
      )
    }
    case 'EncryptStream': {
      const req = request as EncryptStreamRequest
      const bundle = registry.resolve(req.clientId)
      if (!req.plaintext) throw new ServerError('plaintext is required')
      const { data } = await delegated(
        bundle.encryptStream(
          req.plaintext,
          req.encryptionContext,
          req.algorithmSuiteId,
          req.frameLength,
          req.plaintextLengthBound
        )
      )
      return { ciphertext: data }
    }
    case 'DecryptStream': {
      const req = request as DecryptStreamRequest
      const bundle = registry.resolve(req.clientId)
      if (!req.ciphertext) throw new ServerError('ciphertext is required')
      return decryptResponse(
        await delegated(
          bundle.decryptStream(req.ciphertext, req.encryptionContext)
        )
      )
    }
    default:
      throw new ServerError(`unknown operation: ${operation}`)
  }
}

function sendCbor(
  res: http.ServerResponse,
  status: number,
  payload: CborValue
): void {
  if (res.headersSent) {
    res.destroy()
    return
  }
  const body = encode(payload)
  res.writeHead(status, {
    'smithy-protocol': SMITHY_PROTOCOL,
    'content-type': CBOR_CONTENT_TYPE,
    'content-length': body.length,
  })
  res.end(body)
}

function sendError(
  res: http.ServerResponse,
  typeId: string,
  message: string
): void {
  /* Both modeled errors carry @error("client"): HTTP 400. */
  sendCbor(res, 400, { __type: typeId, message })
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

export function createServer(): http.Server {
  const registry = new ClientRegistry()
  return http.createServer((req, res) => {
    handle(registry, req, res).catch((err) => {
      sendError(
        res,
        GENERIC_SERVER_ERROR,
        `unexpected server error: ${describeError(err)}`
      )
    })
  })
}

async function handle(
  registry: ClientRegistry,
  req: http.IncomingMessage,
  res: http.ServerResponse
): Promise<void> {
  const path = req.url ?? ''
  if (req.method !== 'POST' || !path.startsWith(OPERATION_PATH_PREFIX)) {
    sendError(
      res,
      GENERIC_SERVER_ERROR,
      `unknown operation: ${req.method} ${path}`
    )
    return
  }
  if (req.headers['smithy-protocol'] !== SMITHY_PROTOCOL) {
    sendError(
      res,
      GENERIC_SERVER_ERROR,
      'missing or invalid smithy-protocol header; expected rpc-v2-cbor'
    )
    return
  }
  if (req.headers['content-type'] !== CBOR_CONTENT_TYPE) {
    sendError(
      res,
      GENERIC_SERVER_ERROR,
      'missing or invalid content-type; expected application/cbor'
    )
    return
  }
  const operation = path.slice(OPERATION_PATH_PREFIX.length)

  try {
    const body = await readBody(req)
    let request: CborValue
    try {
      request = body.length ? decode(body) : {}
    } catch (err) {
      throw new ServerError(
        `failed to decode CBOR request: ${describeError(err)}`
      )
    }
    if (
      request === null ||
      typeof request !== 'object' ||
      Array.isArray(request) ||
      request instanceof Uint8Array
    ) {
      throw new ServerError('request body must be a CBOR map')
    }
    const response = await dispatch(registry, operation, request)
    sendCbor(res, 200, response)
  } catch (err) {
    if (err instanceof ClientError) {
      sendError(res, ESDK_CLIENT_ERROR, err.message)
    } else if (err instanceof ServerError) {
      sendError(res, GENERIC_SERVER_ERROR, err.message)
    } else {
      sendError(
        res,
        GENERIC_SERVER_ERROR,
        `unexpected server error: ${describeError(err)}`
      )
    }
  }
}
