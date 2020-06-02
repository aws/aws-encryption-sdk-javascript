// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const path = require('path')

module.exports = {
  entry: './src/asdf.test.ts',
  // devtool: 'inline-source-map',
  module: {
    rules: [
      {
        test: /\.asdf.test.ts$/,
        use: 'mocha-loader',
        exclude: /node_modules/
      },
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/
      }
    ]
  },
  resolve: {
    extensions: [ '.tsx', '.ts', '.js' ]
  },
  output: {
    filename: 'asdf.test.js',
    path: path.resolve(__dirname, 'build')
  },
  node: false
}
