// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
  If you are here to disable rules
  to try and fix specific rule sets
  use
  npm install --no-save eslint-nibble
*/

module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    // There is an issue with @typescript-eslint/parser performance.
    // It scales with the number of projects
    // see https://github.com/typescript-eslint/typescript-eslint/issues/1192#issuecomment-596741806
    project: './tsconfig.lint.json',
    tsconfigRootDir: process.cwd(),
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/eslint-recommended',
    'plugin:@typescript-eslint/recommended',
    'prettier',
  ],
  ignorePatterns: ['node_modules/', '*.d.ts'],
  rules: {
    // These are the most useful linting rules.
    // They rely on types so they are the slowest rules,
    // and they are NOT enabled by default on any
    // shared plugins that I know of.
    '@typescript-eslint/no-floating-promises': 'error',
    '@typescript-eslint/promise-function-async': 'error',
    '@typescript-eslint/no-misused-promises': 'error',
    // I disagree with these rules.
    // Humans read from less specific to more specific.
    // No one puts the outline at the end of the book.
    // Since the exported functions should be composed
    // of lower level functions,
    // it is good for understanding
    // for the source files to get more detailed
    // as you read down from the top.
    // Note: eslint has gotten better
    // at parsing typescript
    // and now errors for interfaces as well.
    'no-use-before-define': 'off',
    '@typescript-eslint/no-use-before-define': ['error', { functions: false }],
    // This is used in a few specific ways.
    // It may be that adding this to overrides for the tests
    // and then manual line overrides would be
    // the best way to handle this later.
    '@typescript-eslint/no-explicit-any': 'off',
    // Minimize churn.
    '@typescript-eslint/member-delimiter-style': [
      'error',
      {
        multiline: {
          delimiter: 'none',
          requireLast: false,
        },
        singleline: {
          delimiter: 'semi',
          requireLast: false,
        },
      },
    ],
    // The ESDK exports some interfaces
    // that conflict with this rule.
    // At a later date, this might be
    // able to be turned on,
    // but to ensure ZERO interface changes
    // this rule is disabled.
    // To be clear this would only impact
    // Typescript use of some types/interfaces.
    '@typescript-eslint/no-empty-interface': 'off',
    // To minimize the source change,
    // this is turned of.
    '@typescript-eslint/ban-ts-comment': ['error', { 'ts-ignore': false }],
    // This rule fights with Prettier and no-semi
    '@typescript-eslint/no-extra-semi': 'off',
  },
  // This is a good rule,
  // but in many tests,
  // we are just looking to mock specific functions.
  overrides: [
    {
      files: ['modules/**/test/**/*.ts'],
      rules: {
        '@typescript-eslint/no-empty-function': 'off',
      },
    },
  ],
}
