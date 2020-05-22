// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Karma configuration

module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['mocha', 'chai'],
    files: [
      'test/**/*.ts'
    ],
    preprocessors: {
      'test/**/*.ts': ['webpack', 'credentials']
    },
    webpack: {
      resolve: {
        extensions: [ '.ts', '.js' ]
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
                  configFile: 'tsconfig.module.json',
                  compilerOptions: {
                    rootDir: './'
                  }
                }
              }
            ],
            exclude: /node_modules/,
          },
          {
            test: /\.ts$/,
            exclude: [ /\/test\// ],
            enforce: 'post',
            use: {
              loader: 'istanbul-instrumenter-loader',
              options: { esModules: true }
            }
          }
        ]
      },
      stats: {
        colors: true,
        modules: true,
        reasons: true,
        errorDetails: true
      },
      devtool: 'inline-source-map',
      node: {
        fs: 'empty'
      }
    },
    coverageIstanbulReporter: {
      reports: [ 'json' ],
      dir: '.karma_output',
      fixWebpackSourcePaths: true
    },
    plugins: [
      '@aws-sdk/karma-credential-loader',
      'karma-chrome-launcher',
      'karma-mocha',
      'karma-chai',
      'karma-webpack',
      'karma-coverage-istanbul-reporter'
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
        flags: ['--disable-web-security']
      }
    },
    singleRun: true,
    concurrency: Infinity,
    exclude: ['**/*.d.ts']
  })
}
