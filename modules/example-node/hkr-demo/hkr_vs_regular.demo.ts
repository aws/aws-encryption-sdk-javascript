// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  BranchKeyStoreNode,
  SrkCompatibilityKmsConfig,
  KmsHierarchicalKeyRingNode,
  KmsKeyringNode,
} from '@aws-crypto/client-node'
import { runRoundTrips } from './hkr'
import minimist from 'minimist'

// get cli args
const args = minimist(process.argv.slice(2))
const NUM_ROUNDTRIPS = args.numRoundTrips || 10

// function to run the KMS keyring roundtrips
async function runKmsKeyring() {
  const generatorKeyId =
    'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
  const keyring = new KmsKeyringNode({ generatorKeyId })

  await runRoundTrips(keyring, NUM_ROUNDTRIPS)
}

// function to run the H-keyring roundtrips
async function runKmsHkrKeyring() {
  const branchKeyArn =
    'arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'
  const branchKeyId = '2c583585-5770-467d-8f59-b346d0ed1994'

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

  await runRoundTrips(keyring, NUM_ROUNDTRIPS)
}

async function main() {
  await runKmsKeyring()
  await runKmsHkrKeyring()
}

main()
