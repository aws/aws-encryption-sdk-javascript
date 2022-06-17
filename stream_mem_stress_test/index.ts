// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import express from 'express'
import { kmsDecryptStream, kmsEncryptStream } from './memory'

const app  = express()
const leak = []

app.get('/', (req, res) => {
    // Quick little Test so we can check both in browser and in terminal
    res.write("Test")
    res.send()
    console.log("Back in home")
})

/** This path is here to see how a memory leak would look like in the memory profiler.
 * To test it you can run `npm run load-mem` to see memory get allocated but never
 * garbage collected
 */
app.get('/now', (req, res) => {
    let resp = JSON.stringify({ now: new Date() })
    leak.push(JSON.parse(resp))
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.write(resp)
    res.end()
})

/** Path to read 1mb file, parameter to readFile takes any file in the current directory
 * so you can test with any file you'd like. We supply 2 test files for you to use.
*/
app.get('/readRandom_1mb', (req, res) => {
    res.write("Attempt to encrypt 1mb random")
    // you can optionaly pass in a frame size, otherwise uses the default frame size of 4096 bytes
    readFile('./random_1mb.txt')
    res.send()
})

// Path to decrypt 1mb encrypted file
app.get('/readRandom_1mbEnc', (req, res) => {
    res.write("Attempt to decrypt ./random_1mb.txt.encrypted")
    readEncryptedFile('./random_1mb.txt.encrypted')
    res.send()

})

// Path to encrypt 5mb file
app.get('/readRandom_5mb', (req, res) => {
    res.write("Attempt to encrypt 5mb random")
    readFile('./random_5mb.txt', 1)
    res.send()
})

// Path to decrypt 5mb encrypted file
app.get('/readRandom_5mbEnc', (req, res) => {
    res.write("Attempt to decrypt ./random_5mb.txt.encrypted")
    readEncryptedFile('./random_5mb.txt.encrypted')
    res.send()

})

/** Path to encrypt 1Gb file, not included in this directory because size exceeds GitHub transfer size limit.
 * If you want to create a 1Gb file of random data, you can do so by running
 * `dd if=/dev/urandom of=rand_1gb.txt bs=1024 count=1024000` on a linux system
*/
app.get('/readRandom_1gb', (req, res) => {
    res.write("Attempt to encrypt large random")
    readFile('./rand_1gb.txt')
    res.send()
})

// Path to decrypt 1mb encrypted file
app.get('/readRandom_1gbEnc', (req, res) => {
    res.write("Attempt to encrypt large random")
    kmsDecryptStream('./rand_1gb.txt.encrypted')
    res.send()
})

app.listen(3000, () => {
    console.log("Listening on port 3000");
})

async function readFile(filename:string, framesize?:number) {
    await kmsEncryptStream(filename, framesize);
}

async function readEncryptedFile(filename: string) {
    await kmsDecryptStream(filename)
}
