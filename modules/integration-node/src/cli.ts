#!/usr/bin/env node
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

import yargs from 'yargs'
import { integrationDecryptTestVectors, integrationEncryptTestVectors } from './integration_tests'

const cli = yargs
  .command('decrypt', 'verify decrypt vectors', y => y
    .option('vectorFile', {
      alias: 'v',
      describe: 'a vector zip file from aws-encryption-sdk-test-vectors',
      demandOption: true,
      type: 'string'
    })
  )
  .command('encrypt', 'verify encrypt manifest', y => y
    .option('manifestFile', {
      alias: 'm',
      describe: 'a path/url to aws-crypto-tools-test-vector-framework canonical manifest',
      demandOption: true,
      type: 'string'
    })
    .option('keyFile', {
      alias: 'k',
      describe: 'a path/url to aws-crypto-tools-test-vector-framework canonical key list',
      demandOption: true,
      type: 'string'
    })
    .option('decryptOracle', {
      alias: 'o',
      describe: 'a url to the decrypt oracle',
      demandOption: true,
      type: 'string'
    })
  )
  .option('tolerateFailures', {
    alias: 'f',
    describe: 'an optional number of failures to tolerate before exiting',
    type: 'number',
    default: 0
  })
  .option('testName', {
    alias: 't',
    describe: 'an optional test name to execute',
    type: 'string'
  })
  .option('concurrency', {
    alias: 'c',
    describe: 'an optional concurrency for running tests',
    type: 'number',
    default: 1
  })
  .demandCommand()

;(async (argv) => {
  const { _: [ command ], tolerateFailures, testName, concurrency } = argv
  /* I set the result to 1 so that if I fall through the exit condition is a failure */
  let result = 1
  if (command === 'decrypt') {
    const { vectorFile } = argv as unknown as { vectorFile: string}
    result = await integrationDecryptTestVectors(vectorFile, tolerateFailures, testName, concurrency)
  } else if (command === 'encrypt') {
    const { manifestFile, keyFile, decryptOracle } = argv as unknown as { manifestFile: string, keyFile: string, decryptOracle: string}
    result = await integrationEncryptTestVectors(manifestFile, keyFile, decryptOracle, tolerateFailures, testName, concurrency)
  } else {
    console.log(`Unknown command ${command}`)
    cli.showHelp()
  }

  if (result) process.exit(result)
})(cli.argv)
  .catch(err => {
    console.log(err)
    process.exit(1)
  })
