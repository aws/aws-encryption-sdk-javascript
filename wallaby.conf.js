// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const compilerOptions = Object.assign({
  'esModuleInterop': true,
  'target': 'esnext',
  'module': 'commonjs'
})

module.exports = function (wallaby) {
  return {
    files: [
      'modules/**/src/**/*.ts',
      'modules/**/fixtures.ts',
      '!modules/**/test/**/*.test.ts',
      '!modules/**/node_modules/**',
      '!modules/**/build/**',
      '!modules/*-+(browser|backend)/**/*.ts'
    ],
    tests: [
      'modules/**/test/**/*test.ts',
      '!modules/**/node_modules/**',
      '!modules/**/build/**',
      '!modules/*-+(browser|backend)/**/*.ts'
    ],
    filesWithNoCoverageCalculated: [
      'modules/**/src/index.ts'
    ],
    testFramework: 'mocha',
    compilers: {
      '**/*.ts': wallaby.compilers.typeScript(compilerOptions)
    },
    env: { type: 'node' },
    debug: true,
    setup: w => {
      const { projectCacheDir } = w
      const path = require('path')
      const { Module } = require('module')
      const fs = require('fs')
      if (!Module._originalRequire) {
        const modulePrototype = Module.prototype
        Module._originalRequire = modulePrototype.require
        modulePrototype.require = function (filePath) {
          if (!filePath.startsWith('@aws-crypto')) {
            return Module._originalRequire.call(this, filePath)
          }
          const [, _module] = filePath.split('/')
          const _filePath = path.join(projectCacheDir, 'modules', _module, 'src', 'index.js')
          if (!fs.existsSync(_filePath)) {
            return Module._originalRequire.call(this, filePath)
          }
          return Module._originalRequire.call(this, _filePath)
        }
      }
    }
  }
}
