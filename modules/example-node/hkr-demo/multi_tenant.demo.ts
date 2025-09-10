// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsHierarchicalKeyRingNode,
  BranchKeyStoreNode,
  SrkCompatibilityKmsConfig,
  EncryptionContext,
  buildClient,
  CommitmentPolicy,
  KeyringNode,
  BranchKeyIdSupplier,
} from '@aws-crypto/client-node'
import minimist from 'minimist'
import * as fs from 'fs'
import { exit } from 'process'

// read CLI args
const args = minimist(process.argv.slice(2))

// map A and B to respective branch IDs
const tenantMap: { [key: string]: string } = {
  A: '38853b56-19c6-4345-9cb5-afc2a25dcdd1',
  B: '2c583585-5770-467d-8f59-b346d0ed1994',
}

// preprocess CLI args and return them under an object with named fields
function getCliArgs() {
  const operation = args.operation
  if (!operation) {
    throw new Error('Must specify operation to perform')
  }

  let inFile: string = args.inputFile
  if (!inFile) {
    throw new Error("Must specify input's file path")
  }
  inFile = inFile.replace('~', '/Users/nvobilis')

  let outFile = args.outputFile
  if (!outFile) {
    throw new Error("Must specify output's file path")
  }
  outFile = outFile.replace('~', '/Users/nvobilis')

  const tenant: string = args.tenant
  if (!tenant) {
    throw new Error("Must specify tenant's branch key ID for this operation")
  }

  return { operation, inFile, outFile, tenant }
}

// a dummy branch key id supplier which looks for a field with key "branchKeyId"
// inside the EC
class ExampleBranchKeyIdSupplier implements BranchKeyIdSupplier {
  getBranchKeyId(encryptionContext: EncryptionContext): string {
    return encryptionContext.branchKeyId
  }
}

// configure the keystore
const branchKeyArn =
  'arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'

const keyStore = new BranchKeyStoreNode({
  ddbTableName: 'KeyStoreDdbTable',
  logicalKeyStoreName: 'KeyStoreDdbTable',
  kmsConfiguration: new SrkCompatibilityKmsConfig(branchKeyArn),
})

// function to read input from a file
function readInputData(inFile: string) {
  let inData = Buffer.alloc(0)
  try {
    inData = fs.readFileSync(inFile)
  } catch (err) {
    console.error(err)
    exit(1)
  }

  return inData
}

// a function to write output to a file
function dumpOutputData(outFile: string, outData: Buffer) {
  try {
    fs.writeFileSync(outFile, outData)
  } catch (err) {
    console.error(err)
    exit(1)
  }
}

const { encrypt, decrypt } = buildClient(
  CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

// function to decrypt with the H-keyring
async function decryptEncryptedData(
  encryptedData: Buffer,
  keyring: KeyringNode
) {
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

// function to encrypt with the H-Keyring
async function encryptData(
  data: Buffer,
  keyring: KeyringNode,
  encryptionContext: EncryptionContext
) {
  const { result } = await encrypt(keyring, data, { encryptionContext })
  return result
}

async function main() {
  // read cli args
  const { operation, inFile, outFile, tenant } = getCliArgs()
  // based on CLI tenant arg, find the branch key id
  const branchKeyId: string = tenantMap[tenant]
  // read input from input file
  const inData = readInputData(inFile)

  let outData: Buffer = Buffer.alloc(0)
  let msg: string
  // if cli arg operation field is encrypt
  if (operation === 'encrypt') {
    // create a dynamic keyring and encrypt
    const keyring = new KmsHierarchicalKeyRingNode({
      branchKeyIdSupplier: new ExampleBranchKeyIdSupplier(),
      keyStore,
      cacheLimitTtl: 60,
    })
    const data = inData
    outData = await encryptData(data, keyring, { branchKeyId })
    msg = `Tenant ${tenant} has completed encryption`
  } else {
    // otherwise, create a static keyring and decrypt
    const keyring = new KmsHierarchicalKeyRingNode({
      branchKeyId,
      keyStore,
      cacheLimitTtl: 60,
    })
    const encryptedData = inData

    try {
      outData = await decryptEncryptedData(encryptedData, keyring)
    } catch {
      throw new Error(`Tenant ${tenant} cannot decrypt this encrypted message`)
    }

    msg = `Tenant ${tenant} has completed decryption`
  }

  // write output to output file
  dumpOutputData(outFile, outData)
  console.log(msg)
}

main()
