
const compilerOptions = Object.assign({
    "esModuleInterop": true,
    "target": "esnext",
    "module": "commonjs",
  })

module.exports = function (wallaby) {
  return {
    files: [
      'modules/**/src/**/*.ts',
      'modules/**/fixtures.ts',
      '!modules/**/test/**/*.test.ts',
      '!modules/**/node_modules/**',
      '!modules/**/build/**',
    ],
    tests: [
      'modules/**/test/**/*test.ts',
      '!modules/**/node_modules/**',
      '!modules/**/build/**',
    ],
    filesWithNoCoverageCalculated: [
      'modules/**/src/index.ts'
    ],
    testFramework: 'mocha',
    compilers: {
      '**/*.ts': wallaby.compilers.typeScript(compilerOptions),
    },
    env: { type: 'node' },
    debug: true
  }
}