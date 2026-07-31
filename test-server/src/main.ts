// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Runnable entry point for the Node.js Language_Server.
 *
 * Binds an rpcv2Cbor HTTP endpoint on a port taken from (in order) the first
 * CLI argument, the ESDK_TESTSERVER_PORT env var, or the default 8095.
 */

import { createServer } from './server'

const port = Number(process.argv[2] || process.env.ESDK_TESTSERVER_PORT) || 8095

createServer().listen(port, '127.0.0.1', () => {
  console.log(
    `esdk-test-server (javascript) listening at http://127.0.0.1:${port}`
  )
})
