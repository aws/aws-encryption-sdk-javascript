// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

module.exports = {
  parserOptions: {
    // There is an issue with @typescript-eslint/parser performance.
    // It scales with the number of projects
    // see https://github.com/typescript-eslint/typescript-eslint/issues/1192#issuecomment-596741806
    project: '../../tsconfig.lint.json',
    tsconfigRootDir: __dirname,
  }
}
