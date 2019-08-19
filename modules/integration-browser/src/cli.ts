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
import { spawnSync } from 'child_process'

import { join } from 'path'
import { existsSync, mkdirSync, writeFileSync } from 'fs'
import { buildDecryptFixtures } from './build_decrypt_fixtures'
import { buildEncryptFixtures } from './build_encrypt_fixtures'

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
  .option('testName', {
    alias: 't',
    describe: 'an optional test name to execute',
    type: 'string'
  })
  .option('slice', {
    alias: 's',
    describe: 'an optional range start:end e.g. 100:200',
    type: 'string'
  })
  .options('karma', {
    describe: 'start karma and run the tests',
    type: 'boolean'
  })
  .demandCommand()
const fixtures = join(__dirname, '../../fixtures')
/* Sad side effect. */
if (!existsSync(fixtures)) {
  mkdirSync(fixtures)
}

;(async (argv) => {
  const { _: [ command ], testName, slice, karma, decryptOracle = '' } = argv

  writeFileSync(`${fixtures}/decrypt_tests.json`, JSON.stringify([]))
  writeFileSync(`${fixtures}/encrypt_tests.json`, JSON.stringify([]))
  writeFileSync(`${fixtures}/decrypt_oracle.json`, JSON.stringify(decryptOracle))

  if (command === 'decrypt') {
    const { vectorFile } = argv
    const vectorPath = join(__dirname, vectorFile as string)
    if (!existsSync(vectorPath)) throw new Error(`No file found at ${vectorPath}`)
    // @ts-ignore
    await buildDecryptFixtures(fixtures, vectorFile, testName, slice)
  } else if (command === 'encrypt') {
    const { manifestFile, keyFile } = argv
    // @ts-ignore
    await buildEncryptFixtures(fixtures, manifestFile, keyFile, testName, slice)
  } else {
    console.log(`Unknown command ${command}`)
    cli.showHelp()
  }

  if (karma) {
    spawnSync('npm', ['run', 'karma'], {
      cwd: __dirname,
      stdio: 'inherit'
    })
  }
})(cli.argv)
