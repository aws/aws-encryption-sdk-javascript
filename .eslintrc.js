// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: [
    '@typescript-eslint',
  ],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/eslint-recommended',
    'plugin:@typescript-eslint/recommended',
    'prettier',
  ],
  ignorePatterns: ['node_modules/'],
  rules: {
    // I disagree with this rule.
    // Humans read from less specific to more specific.
    // No on puts the outline at the end of the book.
    // Since the exported functions should be composed
    // of lower level functions,
    // it is good for understanding
    // for the source files to get more detailed
    // as you read down from the top.
    "no-use-before-define": ["error", { "functions": false }],
    "@typescript-eslint/no-use-before-define": ["error", { "functions": false }],
    // This is used in a few specific ways.
    // It may be that adding this to overrides for the tests
    // and then manual line overrides would be
    // the best way to handle this later.
    '@typescript-eslint/no-explicit-any': 'off',
    // Minimize churn.
    '@typescript-eslint/member-delimiter-style': ['error', {
      'multiline': {
        'delimiter': 'none',
        'requireLast': false
      },
      'singleline': {
        'delimiter': 'semi',
        'requireLast': false
      }
    }],
    // The ESDK exports some interfaces
    // that conflict with this rule.
    // At a later date, this might be
    // able to be turned on,
    // but to ensure ZERO interface changes
    // this rule is disabled.
    // To be clear this would only impact
    // Typescript use of some types/interfaces.
    "@typescript-eslint/no-empty-interface": 'off',
    // To minimize the source change,
    // this is turned of.
    "@typescript-eslint/ban-ts-ignore": 'off',
  },
  // This is a good rule,
  // but in many tests,
  // we are just looking to mock specific functions.
  "overrides": [
    {
      "files": ["modules/**/test/**/*.ts"],
      "rules": {
        "@typescript-eslint/no-empty-function": "off"
      }
    }
  ]
};
