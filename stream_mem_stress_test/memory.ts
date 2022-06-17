// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import {
    KmsKeyringNode,
    buildClient,
    CommitmentPolicy
} from '@aws-crypto/client-node'
import {AlgorithmSuiteIdentifier} from '@aws-crypto/material-management'

/* This builds client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy.
 * REQUIRE_ENCRYPT_REQUIRE_DECRYPT enforces that this client only encrypts using committing algorithm suites
 * and enforces that this client will only decrypt encrypted messages
 * that were created with a committing algorithm suite.
 * This is the default if you build `buildClient()`.
 */
const { encryptStream, decryptUnsignedMessageStream } = buildClient(
    CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

import { finished } from 'stream'
import { createReadStream, createWriteStream } from 'fs'
import { promisify } from 'util'
const finishedAsync = promisify(finished)

/* A KMS CMK is required to generate the data key.
 * You need kms:GenerateDataKey permission on the CMK in generatorKeyId.
 * This key is public, DO NOT USE in production environment.
 */
const generatorKeyId = 
    'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

// configure keyring with CMK(s) you wish to work with
const keyring = new KmsKeyringNode({ generatorKeyId })

/**
 * Encryption Context is very useful if you want to assert things about the encrypted data
 * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
 */
const context = {
    stage: 'demo',
    purpose: 'streaming memory stress test',
    origin: 'us-west-2',
}

/**
 * kmsEncryptStream will use the encryptStream function and create a pipeline to encrypt a stream of data
 *  from a file and write it to destination `./{filename}.encrypted`
 * @param filename string of file name you wish to encrypt
 * @param framesize optional parameter to determine frame size; default is 4096 bytes
 */
export async function kmsEncryptStream(filename:string, framesize?:number) {
    const readable = createReadStream(filename)
    const encFile = filename + '.encrypted'
    const writeable = createWriteStream(encFile)
    
    // pipeline of read stream 
    readable.pipe(
        encryptStream(keyring, {
            /**
             * Since we are streaming, and assuming that the encryption and decryption contexts
             * are equally trusted, using an unsigned algorithm suite is faster and avoids
             * the possibility of processing plaintext before the signature is verified.
             */
            suiteId:
                AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
            encryptionContext: context,
            frameLength: framesize
        })
    ).pipe(writeable.on('finish', () => {
        // output from encryptStream will get piped to writeable
        console.log(`The new file name is ${encFile}.`);
    }))   
    
    await finishedAsync(writeable)
    console.log("Finished Encrypting");
    
}
/**
 * kmsDecryptStream will take a filename and create a decryption stream to decrypt contents of file
 * and write it to destination `./{filename}.decrypted
 * @param filename string of file name you wish to encrypt
 */
export async function kmsDecryptStream(filename: string) {
    const readable = createReadStream(filename)
    const decFile = filename + '.decrypted'
    const writeable = createWriteStream(decFile)
    
    readable.pipe(
        /** 
         * decryptUnsignedMessageStream is recommended when streaming if you don't need
         * digital signatures.
         */
        decryptUnsignedMessageStream(keyring)
    ).pipe(writeable.on('finish', () => {
        console.log(`The new file name is ${decFile}.`);
    }))

    await finishedAsync(writeable)
    console.log("Finished Decrypting")
}

