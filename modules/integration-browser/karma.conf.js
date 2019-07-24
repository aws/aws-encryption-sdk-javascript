// Karma configuration
process.env.CHROME_BIN = require('puppeteer').executablePath()

module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['jasmine'],
    files: [
      'fixtures/decrypt_tests.json',
      'fixtures/encrypt_tests.json',
      'fixtures/decrypt_oracle.json',
      { pattern: 'fixtures/*.json', included: false, served: true, watched: false, nocache: true },
      'build/module/integration.decrypt.test.js',
      'build/module/integration.encrypt.test.js',
    ],
    preprocessors: {
      'build/module/integration.decrypt.test.js': ['webpack', 'credentials'],
      'build/module/integration.encrypt.test.js': ['webpack', 'credentials'],
      './fixtures/decrypt_tests.json': ['json_fixtures'],
      './fixtures/encrypt_tests.json': ['json_fixtures'],
      './fixtures/decrypt_oracle.json': ['json_fixtures']

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
        flags: ['--disable-web-security']
      }
    },
    singleRun: true,
    concurrency: Infinity,
    exclude: ['**/*.d.ts']
  })
}
