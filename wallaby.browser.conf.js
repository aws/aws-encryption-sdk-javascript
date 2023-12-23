// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const path = require('path')

module.exports = function (wallaby) {
  console.log(wallaby.compilers.typeScript.toString())
  return {
    files: [
      'modules/**/src/**/*.ts',
      'modules/**/fixtures.ts',
      '!modules/**/test/**/*.test.ts',
      '!modules/**/node_modules/**',
      '!modules/**/build/**',
      '!modules/integration-*/**/*.ts'
    ],
    tests: [
      'modules/*-+(browser|backend)/**/test/**/*test.ts',
      '!modules/**/node_modules/**',
      '!modules/**/build/**',
    ],
    filesWithNoCoverageCalculated: [
      'modules/**/src/index.ts'
    ],
    testFramework: 'mocha',
    postprocessor: wallaby.postprocessors.webpack({
      module: {
        rules: [
          {
            test: /(\.test.ts$|example-browser\/src\/.*\.ts$)/,
            exclude: /node_modules/,
            use: path.resolve('util/wallaby.cred.loader.js')
          },
          {
            test: /\.ts$/,
            exclude: /node_modules/,
            use: {
              loader: 'ts-loader',
              options: {
                transpileOnly: true,
                projectReferences: true,
                configFile: `${__dirname}/tsconfig.module.json`,
              }
            }
          }
        ]
      },
      resolve: {
        extensions: ['.ts', '.js']
      }
    }),
    env: { kind: 'chrome' },
    debug: true,
    setup: function() {
      window.__moduleBundler.loadTests();
    }

  }
}
