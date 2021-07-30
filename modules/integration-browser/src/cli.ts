#!/usr/bin/env node
// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import yargs from 'yargs'
import { spawnSync } from 'child_process'
import { cpus } from 'os'
import { needs } from '@aws-crypto/client-browser'

import { join } from 'path'
import { existsSync, mkdirSync, writeFileSync } from 'fs'
import { buildDecryptFixtures } from './build_decrypt_fixtures'
import { buildEncryptFixtures } from './build_encrypt_fixtures'

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
  .option('testName', {
    alias: 't',
    describe: 'an optional test name to execute',
    type: 'string',
  })
  .option('slice', {
    alias: 's',
    describe: 'an optional range start:end e.g. 100:200',
    type: 'string',
  })
  .options('karma', {
    describe: 'start karma and run the tests',
    type: 'boolean',
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
// This path needs to agree with the path in `karma.conf.js`
const fixtures = join(__dirname, '../../../fixtures')
/* Sad side effect. */
if (!existsSync(fixtures)) {
  mkdirSync(fixtures)
}

;(async (argv) => {
  const {
    _: [command],
    testName,
    slice,
    karma,
    concurrency,
  } = await argv

  writeFileSync(`${fixtures}/decrypt_tests.json`, JSON.stringify([]))
  writeFileSync(`${fixtures}/encrypt_tests.json`, JSON.stringify([]))
  writeFileSync(`${fixtures}/concurrency.json`, JSON.stringify(concurrency))

  if (command === 'decrypt') {
    // It is not clear how to get yargs/typescript to play nicely with sub commands
    const { vectorFile } = argv as unknown as { vectorFile: string }
    if (!existsSync(vectorFile))
      throw new Error(`No file found at ${vectorFile}`)
    await buildDecryptFixtures(fixtures, vectorFile as string, testName, slice)
  } else if (command === 'encrypt') {
    // It is not clear how to get yargs/typescript to play nicely with sub commands
    const { manifestFile, keyFile, decryptOracle } = argv as unknown as {
      manifestFile: string
      keyFile: string
      decryptOracle: string
    }
    writeFileSync(
      `${fixtures}/decrypt_oracle.json`,
      JSON.stringify(decryptOracle)
    )

    await buildEncryptFixtures(
      fixtures,
      manifestFile as string,
      keyFile as string,
      testName,
      slice
    )
  } else {
    console.log(`Unknown command ${command}`)
    cli.showHelp()
  }

  if (karma) {
    const { status } = spawnSync('npm', ['run', 'karma'], {
      cwd: __dirname,
      stdio: 'inherit',
    })
    /* Forward the status to the parent. */
    process.exit(status || 0)
  }
})(cli.argv).catch((err) => {
  console.log(err)
  process.exit(1)
})
