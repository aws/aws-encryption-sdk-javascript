// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const credentialsPromise = require('@aws-sdk/credential-provider-node').defaultProvider()()

module.exports = async function (source, map) {
  console.log('fuck you')
  this.cacheable()
  var callback = this.async()
  const credentials = await credentialsPromise
  var prepend = `var credentials = ${JSON.stringify(credentials)};`
  const newSource = prepend + '\n' + source
  callback(null, newSource, map)
}
