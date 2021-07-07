// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Karma configuration

const credentialsPromise =
  require('@aws-sdk/credential-provider-node').defaultProvider()()
const webpack = require('webpack')

module.exports = function (config) {
  process.on('infrastructure_error', (error) => {
    /* @aws-sdk/karma-credential-loader get credential
     * as configured by the AWS SDK.
     * These credentials are used to test KMS integration
     * with the Encryption SDK.
     * If they do not exist, then karma will exit with an `UnhandledRejection`.
     * The following will log errors link this,
     * but still let the karma-server shut down.
     */
    console.error('infrastructure_error', error)
  })

  config.set({
    basePath: '',
    frameworks: [ 'mocha', 'chai', 'webpack'],
    files: [
      'modules/*-browser/build/module/test/*.js',
      'modules/material-management/build/module/test/*.js',
      'modules/raw-keyring/build/module/test/*.js',
      'modules/kms-keyring/build/module/test/*.js',
      // 'modules/cache-material/build/module/test/*.js',
      'modules/serialize/build/module/test/*.js',
      'modules/web-crypto-backend/build/module/test/*.js',
    ],
    preprocessors: {
      'modules/**/build/module/test/*.js': ['webpack', 'credentials'],
    },
    webpack: {
      resolve: {
        extensions: ['.js'],
      },
      mode: 'development',
      module: {
        rules: [
          {
            // yauzl is only used in the node cli for browser integration
            test: /yauzl/,
            use: 'null-loader',
          },
          {
            test: /\.js/,
            // msrcrypto.js is are outside dependances
            // and should not be intremented or impact code coverage.
            // fixtures.js is a test file, not an entry point
            exclude: /(node_modules)|(msrcrypto.js)|(fixtures.js)/,
            use: {
              loader: "@jsdevtools/coverage-istanbul-loader",
              options: {
                // produceSourceMap: true
              }
            }
          }
        ],
      },
      plugins: [
        new webpack.ProvidePlugin({
          Buffer: ['buffer', 'Buffer'],
        }),
      ],
      stats: {
        colors: true,
        modules: true,
        reasons: true,
        errorDetails: true,
      },
      devtool: 'source-map',
      resolve: {
        fallback: {
          fs: false,
          crypto: false,
        },
      },
    },
    coverageIstanbulReporter: {
      reports: ['json'],
      combineBrowserReports: true,
      fixWebpackSourcePaths: true,
      dir: '.karma_output',
      skipFilesWithNoCoverage: true,
      // verbose: true,
    },
    plugins: [
      {
        'preprocessor:credentials': ['factory', createCredentialPreprocessor],
      },
      'karma-chrome-launcher',
      'karma-mocha',
      'karma-chai',
      'karma-webpack',
      'karma-coverage-istanbul-reporter',
      'karma-json-fixtures-preprocessor',
    ],
    reporters: ['progress', 'coverage-istanbul'],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: false,
    browsers: ['ChromeHeadlessDisableCors'],
    customLaunchers: {
      ChromeHeadlessDisableCors: {
        base: 'ChromeHeadless',
        flags: ['--disable-web-security', '--no-sandbox'],
      },
    },
    singleRun: true,
    concurrency: Infinity,
    exclude: ['**/*.d.ts'],
  })
}

function createCredentialPreprocessor() {
  return async function (content, file, done) {
    // strip the extension from the file since it won't match the preprocessor pattern
    const fileName = file.originalPath
    // add region and credentials to each file
    const region = process.env.AWS_SMOKE_TEST_REGION || ''
    const credentials = await credentialsPromise
    // This will affect the generated (ES5) JS
    const regionCode = `var defaultRegion = '${region}';`
    const credentialsCode = `var credentials = ${JSON.stringify(credentials)};`
    const isBrowser = `var isBrowser = true;`
    const contents = content.split('\n')
    let idx = -1
    for (let i = 0; i < contents.length; i++) {
      const line = contents[i]
      if (line.indexOf(fileName) !== -1) {
        idx = i
        break
      }
    }
    contents.splice(idx + 1, 0, regionCode, credentialsCode, isBrowser)
    done(contents.join('\n'))
  }
}
