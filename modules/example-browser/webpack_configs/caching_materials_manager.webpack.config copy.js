const webpack = require('webpack')
const path = require('path')
const {defaultProvider} = require('@aws-sdk/credential-provider-node')

module.exports = (async () => ({
  entry: './src/caching_materials_manager.ts',
  // devtool: 'inline-source-map',
  module: {
    rules: [
      {
        test: /caching_materials_manager.ts$/,
        use: [
          {
            loader: 'ts-loader',
            options: {
              configFile: 'tsconfig.module.json'
            }
          }
        ],
        include: /caching_materials_manager.ts/,
        exclude: [/node_modules/]
      }
    ]
  },
  resolve: {
    extensions: [ '.tsx', '.ts', '.js' ]
  },
  output: {
    filename: 'caching_materials_manager_bundle.js',
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
