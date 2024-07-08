// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const compilerOptions = Object.assign({
  'esModuleInterop': true,
  'target': 'esnext',
  'module': 'commonjs'
})

module.exports = function (wallaby) {
  var path = require('path');
  process.env.NODE_PATH += path.delimiter + path.join(wallaby.localProjectDir, 'core', 'node_modules');

  return {
    files: [
      'modules/**/src/**/*.ts',
      'modules/**/fixtures.ts',
      { pattern: 'modules/**/test/**/*.test.ts', ignore: true},
      { pattern: 'modules/**/node_modules/**', ignore: true},
      { pattern: 'modules/**/build/**', ignore: true},
      { pattern: 'modules/*-browser/**/*.ts', ignore: true},
      { pattern: 'modules/*-backend/**/*.ts', ignore: true},
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
  }
}
