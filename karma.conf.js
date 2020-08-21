// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Karma configuration

const credentialsPromise = require('@aws-sdk/credential-provider-node').defaultProvider()()

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
    frameworks: ['mocha', 'chai'],
    files: [
      'modules/*-browser/test/**/*.ts',
      'modules/web-crypto-backend/test/**/*.ts',
    ],
    preprocessors: {
      'modules/*-browser/test/**/*.ts': ['webpack', 'credentials'],
      'modules/web-crypto-backend/test/**/*.ts': ['webpack', 'credentials'],
    },
    webpack: {
      resolve: {
        extensions: ['.ts', '.js'],
      },
      mode: 'development',
      module: {
        rules: [
          {
            test: /\.tsx?$/,
            use: [
              {
                loader: 'ts-loader',
                options: {
                  logInfoToStdOut: true,
                  projectReferences: true,
                  configFile: `${__dirname}/tsconfig.module.json`,
                },
              },
            ],
            exclude: /node_modules/,
          },
          {
            test: /\.ts$/,
            exclude: [/\/test\//],
            enforce: 'post',
            use: {
              loader: 'istanbul-instrumenter-loader',
              options: { esModules: true },
            },
          },
        ],
      },
      stats: {
        colors: true,
        modules: true,
        reasons: true,
        errorDetails: true,
      },
      devtool: 'inline-source-map',
      node: {
        fs: 'empty',
      },
    },
    coverageIstanbulReporter: {
      reports: ['json'],
      dir: '.karma_output',
      fixWebpackSourcePaths: true,
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
