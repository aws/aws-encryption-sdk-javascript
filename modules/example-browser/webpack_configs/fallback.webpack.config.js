// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const path = require('path')

module.exports = {
  entry: './src/fallback.ts',
  // devtool: 'inline-source-map',
  module: {
    rules: [
      {
        test: /fallback.ts$/,
        use: [
          {
            loader: 'ts-loader',
            options: {
              configFile: 'tsconfig.module.json'
            }
          }
        ],
        include: /fallback.ts/,
        exclude: [/node_modules/]
      }
    ]
  },
  resolve: {
    extensions: [ '.tsx', '.ts', '.js' ]
  },
  output: {
    filename: 'fallback_bundle.js',
    path: path.resolve(__dirname, '..', 'build'),
    library: 'test',
    libraryTarget: 'var'
  }
}
