// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'fs'
import {
  BranchKeyStoreNode,
  buildClient,
  CommitmentPolicy,
  KmsHierarchicalKeyRingNode,
  SrkCompatibilityKmsConfig,
} from '@aws-crypto/client-node'
import { exit } from 'process'

const { encrypt, decrypt } = buildClient(
  CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

// create H-Keyring
const branchKeyArn =
  'arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'
const branchKeyId = '38853b56-19c6-4345-9cb5-afc2a25dcdd1'

const keyStore = new BranchKeyStoreNode({
  ddbTableName: 'KeyStoreDdbTable',
  logicalKeyStoreName: 'KeyStoreDdbTable',
  kmsConfiguration: new SrkCompatibilityKmsConfig(branchKeyArn),
})

const keyring = new KmsHierarchicalKeyRingNode({
  branchKeyId,
  keyStore,
  cacheLimitTtl: 60,
})

// function to decrypt with H-Keyring
async function decryptEncryptedData(encryptedData: Buffer) {
  const { plaintext: decryptedData, messageHeader } = await decrypt(
    keyring,
    encryptedData
  )

  const { encryptionContext } = messageHeader

  Object.entries(encryptionContext).forEach(([key, value]) => {
    if (encryptionContext[key] !== value) {
      throw new Error('Encryption Context does not match expected values')
    }
  })

  return decryptedData
}

// function to encrypt with H-Keyring
async function encryptData(data: Buffer) {
  const { result } = await encrypt(keyring, data, {
    encryptionContext: { successful: 'demo' },
  })

  return result
}

async function main() {
  // read CLI args
  const args = process.argv.slice(2)
  const operation = args[0]
  const inFile = args[1]
  const outFile = args[2]

  // read from input file
  let inData = Buffer.alloc(0)
  try {
    inData = fs.readFileSync(inFile)
  } catch (err) {
    console.error(err)
    exit(1)
  }

  // encrypt/decrypt input file
  let outData: Buffer
  let msg: string
  if (operation === 'encrypt') {
    const data = inData
    outData = await encryptData(data)
    msg = 'JS has completed encryption'
  } else {
    const encryptedData = inData
    outData = await decryptEncryptedData(encryptedData)
    msg = 'JS has completed decryption'
  }

  // write to output file
  try {
    fs.writeFileSync(outFile, outData)
  } catch (err) {
    console.error(err)
    exit(1)
  }

  // log completion message
  console.log(msg)
}

main()
