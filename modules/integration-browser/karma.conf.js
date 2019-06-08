// Karma configuration
process.env.CHROME_BIN = require('puppeteer').executablePath()

module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['jasmine'],
    files: [
      'fixtures/tests.json',
      { pattern: 'fixtures/*.json', included: false, served: true, watched: false, nocache: true },
      'src/integration.test.ts'
    ],
    preprocessors: {
      './src/*.test.ts': ['webpack', 'credentials'],
      './fixtures/tests.json': ['json_fixtures']
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
            use: 'ts-loader',
            exclude: /node_modules/
          }
        ]
      },
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
