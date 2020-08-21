# AWS Encryption SDK for JavaScript client for Node.js

# @aws-crypto/client-node

The *client-node* module includes all of the modules you need to use the AWS Encryption SDK for
JavaScript with Node.js. 

* decrypt-node
* encrypt-node
* kms-keyring-node
* material-management-node
* caching-materials-manager-node
* raw-aes-keyring-node
* raw-rsa-keyring-node

For code examples that show you how to these modules to create keyrings and encrypt and decrypt data, install the [example-node](https://github.com/aws/aws-encryption-sdk-javascript/tree/master/modules/example-node) module. 
## install

To install this module, use the npm package manager. For help with installation, see
[https://www.npmjs.com/get-npm](https://www.npmjs.com/get-npm). 

```sh
npm install @aws-crypto/client-node
```

## use

For detailed code examples
that show you how to these modules
to create keyrings 
and encrypt and decrypt data,
install the [example-node](https://github.com/aws/aws-encryption-sdk-javascript/tree/master/modules/example-node) module. 

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

/* Create the KMS keyring */
const keyring = new KmsKeyringNode({ generatorKeyId, keyIds })

/* Set an encryption context For more information: 
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
 */
const context = {
    stage: 'demo',
    purpose: 'simple demonstration app',
    origin: 'us-west-2'
  }
 
/* Create a string to encrypt */
const cleartext = 'asdf'

/* Encrypt the string using the keyring and the encryption context 
 * the Encryption SDK returns an "encrypted message" (`result`) that includes the ciphertext
 * the encryption context, and the encrypted data keys.
 */ 
const { result } = await encrypt(keyring, cleartext, { encryptionContext: context })

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

/* If the encryption context is verified, return the plaintext. */

```

## test

```sh
npm test
```

## Compatibility Considerations

### RSA Options

Node.js crypto does not support all RSA key wrapping options supported by other other implementation of the AWS Encryption SDK

The supported configurations are:

* OAEP with SHA1 and MGF1 with SHA1
* PKCS1v15

## license

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.

