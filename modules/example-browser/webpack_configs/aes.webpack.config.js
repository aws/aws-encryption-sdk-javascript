// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const path = require('path')

module.exports = {
  entry: './src/aes_simple.ts',
  // devtool: 'inline-source-map',
  module: {
    rules: [
      {
        test: /aes_simple.ts$/,
        use: [
          {
            loader: 'ts-loader',
            options: {
              configFile: 'tsconfig.module.json'
            }
          }
        ],
        include: /aes_simple.ts/,
        exclude: [/node_modules/]
      }
    ]
  },
  resolve: {
    extensions: [ '.tsx', '.ts', '.js' ]
  },
  output: {
    filename: 'aes_simple_bundle.js',
    path: path.resolve(__dirname, '..', 'build'),
    library: 'test',
    libraryTarget: 'var'
  }
}
