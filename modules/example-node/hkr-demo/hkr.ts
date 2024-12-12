// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  buildClient,
  CommitmentPolicy,
  KeyringNode,
  EncryptionContext,
} from '@aws-crypto/client-node'
import { randomBytes } from 'crypto'
import { KMSClient } from '@aws-sdk/client-kms'
import sinon from 'sinon'
import { DynamoDBClient } from '@aws-sdk/client-dynamodb'

const { encrypt, decrypt } = buildClient(
  CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)
const MAX_INPUT_LENGTH = 20
const MIN_INPUT_LENGTH = 15
const PURPLE_LOG = '\x1b[35m%s\x1b[0m'
const YELLO_LOG = '\x1b[33m%s\x1b[0m'
const GREEN_LOG = '\x1b[32m%s\x1b[0m'
const RED_LOG = '\x1b[31m%s\x1b[0m'

// function to generate a random string
export function generateRandomString(minLength: number, maxLength: number) {
  const randomLength =
    Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength
  return randomBytes(randomLength).toString('hex').slice(0, randomLength)
}

// function to encrypt, decrypt, and verify
export async function roundtrip(
  keyring: KeyringNode,
  context: EncryptionContext,
  cleartext: string
) {
  const { result } = await encrypt(keyring, cleartext, {
    encryptionContext: context,
  })

  const { plaintext, messageHeader } = await decrypt(keyring, result)

  const { encryptionContext } = messageHeader

  Object.entries(context).forEach(([key, value]) => {
    if (encryptionContext[key] !== value) {
      throw new Error('Encryption Context does not match expected values')
    }
  })

  return { plaintext, result, cleartext, messageHeader }
}

// run the roundtrips on the specified keyring
export async function runRoundTrips(
  keyring: KeyringNode,
  numRoundTrips: number
) {
  // set up spies to monitor network call volume
  const kmsSpy = sinon.spy(KMSClient.prototype, 'send')
  const ddbSpy = sinon.spy(DynamoDBClient.prototype, 'send')
  const padding = String(numRoundTrips).length
  let successes = 0

  console.log()
  console.log(YELLO_LOG, `${keyring.constructor.name} Roundtrips`) // Print constructor name in yellow
  console.time('Total runtime') // Start the timer

  // for each roundtrip
  for (let i = 0; i < numRoundTrips; i++) {
    // create an encryption context
    const encryptionContext = {
      roundtrip: i.toString(),
    }
    // generate a random string
    const encryptionInput = generateRandomString(
      MIN_INPUT_LENGTH,
      MAX_INPUT_LENGTH
    )

    // try to do the roundtrip. If any error arises, log it properly
    let decryptionOutput: string
    try {
      const { plaintext } = await roundtrip(
        keyring,
        encryptionContext,
        encryptionInput
      )
      decryptionOutput = plaintext.toString()
    } catch {
      decryptionOutput = 'ERROR'
    }

    const encryptionInputPadding = ' '.repeat(
      MAX_INPUT_LENGTH - encryptionInput.length
    )
    const decryptionOutputPadding = ' '.repeat(
      MAX_INPUT_LENGTH - decryptionOutput.length
    )

    // log message
    const logMessage = `Roundtrip ${String(i + 1).padStart(
      padding,
      ' '
    )}: ${encryptionInput}${encryptionInputPadding} ----encrypt & decrypt----> ${decryptionOutput}${decryptionOutputPadding}`

    // print the log green if successful. Otherwise, red
    let logColor: string
    if (encryptionInput === decryptionOutput) {
      logColor = GREEN_LOG
      successes += 1
    } else {
      logColor = RED_LOG
    }
    console.log(logColor, logMessage)
  }

  // print metrics for runtime and call volume
  console.log()
  console.log(YELLO_LOG, `${keyring.constructor.name} metrics`) // Print constructor name in yellow
  console.timeEnd('Total runtime')
  console.log(PURPLE_LOG, `KMS calls: ${kmsSpy.callCount}`)
  console.log(PURPLE_LOG, `DynamoDB calls: ${ddbSpy.callCount}`)
  console.log(
    PURPLE_LOG,
    `Successful roundtrips: ${successes} / ${numRoundTrips}`
  )

  kmsSpy.restore()
  ddbSpy.restore()
}
