# AWS Encryption SDK for JavaScript client for the Browser

# @aws-crypto/client-browser

The *client-browser* module includes all of the modules you need to use the AWS Encryption SDK for
the JavaScript web browser.

* decrypt-browser
* encrypt-browser
* kms-keyring-browser
* material-management-browser
* caching-materials-manager-browser
* raw-aes-keyring-browser
* raw-rsa-keyring-browser
* web-crypto-backend

For code examples that show you how to these modules to create keyrings and encrypt and decrypt data, install the [example-browser](https://github.com/aws/aws-encryption-sdk-javascript/tree/master/modules/example-browser) module. 
## install

To install this module, use the npm package manager. For help with installation, see
[https://www.npmjs.com/get-npm](https://www.npmjs.com/get-npm). 

```sh
npm install @aws-crypto/client-browser
```

## use

For detailed code examples
that show you how to these modules
to create keyrings 
and encrypt and decrypt data,
install the [example-browser](https://github.com/aws/aws-encryption-sdk-javascript/tree/master/modules/example-browser) module. 

```javascript

/* Start by constructing a keyring. We'll create a KMS keyring.
 * Specify an AWS Key Management Service (AWS KMS) customer master key (CMK) to be the
 * generator key in the keyring. This CMK generates a data key and encrypts it. 
 * To use the keyring to encrypt data, you need kms:GenerateDataKey permission 
 * on this CMK. To decrypt, you need kms:Decrypt permission. 
 */
const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

/* You can specify additional CMKs for the keyring. The data key that the generator key
 * creates is also encrypted by the additional CMKs you specify. To encrypt data, 
 *  you need kms:Encrypt permission on this CMK. To decrypt, you need kms:Decrypt permission.
 */ 
const keyIds = ['arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f']

/* Create a KMS client provider with your AWS credentials */
const clientProvider = getClient(KMS, {
  credentials: {
    accessKeyId,
    secretAccessKey
  }
})

/* Create the KMS keyring */
const keyring = new KmsKeyringBrowser({ clientProvider, generatorKeyId, keyIds })

/* Set an encryption context For more information: 
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
 */
const context = {
    stage: 'demo',
    purpose: 'simple demonstration app',
    origin: 'us-west-2'
  }
 
/* Create a string to encrypt */
const plainText = new Uint8Array([1, 2, 3, 4, 5])

/* Encrypt the string using the keyring and the encryption context 
 * the Encryption SDK returns an "encrypted message" (`result`) that includes the ciphertext, 
 * the encryption context, and the encrypted data keys.
 */ 
const { result } = await encrypt(keyring, plainText, { encryptionContext: context })

/* Decrypt the result using the same keyring */
const { plaintext, messageHeader } = await decrypt(keyring, result)

/* Get the encryption context */
const { encryptionContext } = messageHeader

/* Verify that all values in the original encryption context are in the 
 * current one. (The Encryption SDK adds extra values for signing.) 
 */
Object
  .entries(context)
  .forEach(([key, value]) => {
    if (encryptionContext[key] !== value) throw new Error('Encryption Context does not match expected values')
    })

/* If the encryption context is verified, log the plaintext. */
document.write('</br>Decrypted:' + plaintext)
console.log(plaintext)

```

## test

```sh
npm test
```

## Compatibility Considerations

### WebCrypto availability

The WebCrypto API is not available on all browsers.
A fallback can be configured.
An example of a fallback library is:
[MSR Crypto](https://www.microsoft.com/en-us/research/project/msr-javascript-cryptography-library/)
```javascript
import { configureFallback } from '@aws-crypto/client-browser'
configureFallback(msrCrypto)
```

For details on `configureFallback` see: [@aws-crypto/web-crypto-backend](https://npmjs.com/package/@aws-crypto/web-crypto-backend)

### Zero Byte AES-GCM operations

Modern versions of Safari do not support AES-GCM on zero bytes.
The AWS Encryption SDK needs this to operate.
To fix this, configure a fallback library exactly as above.
The AWS Encryption SDK will only use the fallback for zero byte operations.

### RSA Options

The WebCrypto API does not support `PKCS1v15` RSA key wrapping.

### 192 Bit Keys

Browsers do not support key lengths of 192 bits.

## license

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.

