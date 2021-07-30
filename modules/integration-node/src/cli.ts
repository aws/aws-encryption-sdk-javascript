#!/usr/bin/env node
// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import yargs from 'yargs'
import { needs } from '@aws-crypto/client-node'
import { cpus } from 'os'
import {
  integrationDecryptTestVectors,
  integrationEncryptTestVectors,
} from './integration_tests'

const cli = yargs
  .command('decrypt', 'verify decrypt vectors', (y) =>
    y.option('vectorFile', {
      alias: 'v',
      describe: 'a vector zip file from aws-encryption-sdk-test-vectors',
      demandOption: true,
      type: 'string',
    })
  )
  .command('encrypt', 'verify encrypt manifest', (y) =>
    y
      .option('manifestFile', {
        alias: 'm',
        describe:
          'a path/url to aws-crypto-tools-test-vector-framework canonical manifest',
        demandOption: true,
        type: 'string',
      })
      .option('keyFile', {
        alias: 'k',
        describe:
          'a path/url to aws-crypto-tools-test-vector-framework canonical key list',
        demandOption: true,
        type: 'string',
      })
      .option('decryptOracle', {
        alias: 'o',
        describe: 'a url to the decrypt oracle',
        demandOption: true,
        type: 'string',
      })
  )
  .option('tolerateFailures', {
    alias: 'f',
    describe: 'an optional number of failures to tolerate before exiting',
    type: 'number',
    default: 0,
  })
  .option('testName', {
    alias: 't',
    describe: 'an optional test name to execute',
    type: 'string',
  })
  .option('concurrency', {
    alias: 'c',
    describe: `an optional concurrency for running tests, pass 'cpu' to maximize`,
    default: 1,
    coerce: (value: any) => {
      if (typeof value === 'string') {
        needs(
          value.toLowerCase() === 'cpu',
          `The only supported string is 'cpu'`
        )
        return cpus().length - 1
      }
      needs(
        typeof value === 'number' && value > 0,
        `Must be a number greater than 0`
      )
      return value
    },
  })
  .demandCommand()

;(async (argv) => {
  const {
    _: [command],
    tolerateFailures,
    testName,
    concurrency,
  } = argv
  /* I set the result to 1 so that if I fall through the exit condition is a failure */
  let result = 1
  if (command === 'decrypt') {
    const { vectorFile } = argv as unknown as { vectorFile: string }
    result = await integrationDecryptTestVectors(
      vectorFile,
      tolerateFailures,
      testName,
      concurrency
    )
  } else if (command === 'encrypt') {
    const { manifestFile, keyFile, decryptOracle } = argv as unknown as {
      manifestFile: string
      keyFile: string
      decryptOracle: string
    }
    result = await integrationEncryptTestVectors(
      manifestFile,
      keyFile,
      decryptOracle,
      tolerateFailures,
      testName,
      concurrency
    )
  } else {
    console.log(`Unknown command ${command}`)
    cli.showHelp()
  }

  if (result) process.exit(result)
})(cli.argv).catch((err) => {
  console.log(err)
  process.exit(1)
})
