// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* The two modeled error shapes. ClientError -> ESDKClientError (failures
 * originating in the ESDK under test); ServerError -> GenericServerError
 * (framework/config failures). Both serialize as HTTP 400 with a CBOR map
 * carrying the __type discriminator.
 */

const NAMESPACE = 'aws.cryptography.esdk.testserver'
export const GENERIC_SERVER_ERROR = `${NAMESPACE}#GenericServerError`
export const ESDK_CLIENT_ERROR = `${NAMESPACE}#ESDKClientError`

export class ClientError extends Error {}

export class ServerError extends Error {}

/* Flatten an unknown thrown value to a message. */
export function describeError(err: unknown): string {
  if (err instanceof Error) return err.message
  return String(err)
}
