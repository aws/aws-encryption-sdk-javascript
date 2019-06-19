const webpack = require('webpack')
const path = require('path')
const {defaultProvider} = require('@aws-sdk/credential-provider-node')

module.exports = (async () => ({
  entry: './src/multi_keyring.ts',
  // devtool: 'inline-source-map',
  module: {
    rules: [
      {
        test: /multi_keyring.ts$/,
        use: [
          {
            loader: 'ts-loader',
            options: {
              configFile: 'tsconfig.module.json'
            }
          }
        ],
        include: /multi_keyring.ts/,
        exclude: [/node_modules/]
      }
    ]
  },
  resolve: {
    extensions: [ '.tsx', '.ts', '.js' ]
  },
  output: {
    filename: 'multi_keyring_bundle.js',
    path: path.resolve(__dirname, '..', 'build')
  },
  plugins: [
    new webpack.DefinePlugin({
      'AWS_CREDENTIALS': JSON.stringify(await defaultProvider()())
    })
  ],
  node: {
    util: 'empty'
  }
}))()
