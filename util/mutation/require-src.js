// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Mocha loads this file before the tests when Stryker runs them (stryker.config.json).
// Stryker writes its mutants into the TypeScript under modules/*/src.
// A test imports another module by its package name, for example `@aws-crypto/material-management`,
// and node_modules maps that name to the module's compiled build/, which has no mutants.
// So this hook maps each package name to the module's src/index.ts, and ts-node compiles it.
// A test in encrypt-node can then kill a mutant in material-management.

const fs = require('fs')
const Module = require('module')
const path = require('path')

const modules = path.join(__dirname, '..', '..', 'modules')

require('ts-node').register({
  project: path.join(modules, 'tsconfig.settings.json'),
  // Stryker marks the files it mutates with @ts-nocheck, and type checking every test run costs minutes.
  transpileOnly: true,
})

const resolve = Module._resolveFilename
Module._resolveFilename = function (request, ...rest) {
  const match = /^@aws-crypto\/([a-z0-9-]+)$/.exec(request)
  if (match) {
    const index = path.join(modules, match[1], 'src', 'index.ts')
    if (fs.existsSync(index)) return index
  }
  return resolve.call(this, request, ...rest)
}
