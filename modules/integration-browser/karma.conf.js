// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Karma configuration
const { readFileSync } = require('fs')
const credentialsPromise =
  require('@aws-sdk/credential-provider-node').defaultProvider()()
const webpack = require('webpack')

module.exports = function (config) {
  // karma-parallel will use the number CPUs as the default number of browsers to spawn
  // But ideally this would be a command line option.
  // Since I'm already using these files to pass information back and forth,
  // I'm just coopting the path.
  const concurrency = JSON.parse(readFileSync('./fixtures/concurrency.json'))
  config.set({
    basePath: '',
    frameworks: ['parallel', 'jasmine'],
    files: [
      'fixtures/decrypt_tests.json',
      'fixtures/encrypt_tests.json',
      'fixtures/decrypt_oracle.json',
      'fixtures/concurrency.json',
      {
        pattern: 'fixtures/*.json',
        included: false,
        served: true,
        watched: false,
        nocache: true,
      },
      'build/module/src/*test.js',
    ],
    preprocessors: {
      './build/module/src/*.js': ['webpack', 'credentials'],
      './fixtures/decrypt_tests.json': ['json_fixtures'],
      './fixtures/encrypt_tests.json': ['json_fixtures'],
      './fixtures/decrypt_oracle.json': ['json_fixtures'],
      './fixtures/concurrency.json': ['json_fixtures'],
    },
    webpack: {
      module: {
        rules: [
          {
            // yauzl is only used in the node cli for browser integration
            test: /yauzl/,
            use: 'null-loader',
          },
        ]
      },
      mode: 'development',
      stats: {
        colors: true,
        modules: true,
        reasons: true,
        errorDetails: true,
      },
      plugins: [
        new webpack.ProvidePlugin({
          Buffer: ['buffer', 'Buffer'],
        }),
      ],
      devtool: 'inline-source-map',
      resolve: {
        fallback: {
          fs: false,
          crypto: false,
        },
      },
    },
    plugins: [
      {
        'preprocessor:credentials': ['factory', createCredentialPreprocessor],
      },
      'karma-parallel',
      'karma-webpack',
      'karma-json-fixtures-preprocessor',
      'karma-chrome-launcher',
      'karma-jasmine',
    ],
    reporters: ['progress'],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: false,
    browsers: ['ChromeHeadlessDisableCors'],
    customLaunchers: {
      ChromeHeadlessDisableCors: {
        base: 'ChromeHeadless',
        flags: [
          '--headless',
          '--disable-web-security',
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--enable-logging',
        ],
      },
    },
    singleRun: true,
    concurrency: Infinity,
    exclude: ['**/*.d.ts'],
    parallelOptions: {
      executors: concurrency,
    },
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
    // See: https://github.com/aws/aws-sdk-js-v3/issues/5890
    const expirationNeedsToBeDate = `credentials.expiration = new Date(credentials.expiration);`
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
    contents.splice(idx + 1, 0, regionCode, credentialsCode, expirationNeedsToBeDate, isBrowser)
    done(contents.join('\n'))
  }
}
