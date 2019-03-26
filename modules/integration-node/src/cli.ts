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
import { integrationTestVectors } from './integration_tests'

const argv = yargs
  .option('vectorFile', {
    alias: 'v',
    describe: 'a vector zip file from aws-encryption-sdk-test-vectors',
    demandOption: true,
    type: 'string'
  })
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
  .argv

const { vectorFile, tolerateFailures, testName } = argv
integrationTestVectors(vectorFile, tolerateFailures, testName)
