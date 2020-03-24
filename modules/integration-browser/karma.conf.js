// Karma configuration
const { readFileSync } = require('fs')

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
      '/fixtures/concurrency.json',
      { pattern: 'fixtures/*.json', included: false, served: true, watched: false, nocache: true },
      'build/module/integration.decrypt.test.js',
      'build/module/integration.encrypt.test.js',
    ],
    preprocessors: {
      'build/module/integration.decrypt.test.js': ['webpack', 'credentials'],
      'build/module/integration.encrypt.test.js': ['webpack', 'credentials'],
      './fixtures/decrypt_tests.json': ['json_fixtures'],
      './fixtures/encrypt_tests.json': ['json_fixtures'],
      './fixtures/decrypt_oracle.json': ['json_fixtures'],
      './fixtures/concurrency.json': ['json_fixtures'],
    },
    webpack: {
      mode: 'development',
      stats: {
        colors: true,
        modules: true,
        reasons: true,
        errorDetails: true
      },
      devtool: 'inline-source-map'
    },
    plugins: [
      'karma-parallel',
      '@aws-sdk/karma-credential-loader',
      'karma-webpack',
      'karma-json-fixtures-preprocessor',
      'karma-chrome-launcher',
      'karma-jasmine'
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
        ]
      }
    },
    singleRun: true,
    concurrency: Infinity,
    exclude: ['**/*.d.ts'],
    parallelOptions: {
      executors: concurrency
    }
  })
}
