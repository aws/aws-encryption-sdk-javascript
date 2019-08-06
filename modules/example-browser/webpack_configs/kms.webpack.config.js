const webpack = require('webpack')
const path = require('path')
const {defaultProvider} = require('@aws-sdk/credential-provider-node')

module.exports = (async () => ({
  entry: './src/kms_simple.ts',
  // devtool: 'inline-source-map',
  module: {
    rules: [
      {
        test: /kms_simple.ts$/,
        use: [
          {
            loader: 'ts-loader',
            options: {
              configFile: 'tsconfig.module.json'
            }
          }
        ],
        include: /kms_simple.ts/,
        exclude: [/node_modules/]
      }
    ]
  },
  resolve: {
    extensions: [ '.tsx', '.ts', '.js' ]
  },
  output: {
    filename: 'kms_simple_bundle.js',
    path: path.resolve(__dirname, '..', 'build'),
    library: 'test',
    libraryTarget: 'var'
  },
  plugins: [
    new webpack.DefinePlugin({
      credentials: JSON.stringify(await defaultProvider()())
    })
  ],
  node: {
    util: 'empty'
  }
}))()
