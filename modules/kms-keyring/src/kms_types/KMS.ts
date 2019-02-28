
import {DecryptInput} from './DecryptInput';
import {DecryptOutput} from './DecryptOutput';

import {EncryptInput} from './EncryptInput';
import {EncryptOutput} from './EncryptOutput';

import {GenerateDataKeyInput} from './GenerateDataKeyInput';
import {GenerateDataKeyOutput} from './GenerateDataKeyOutput';

export interface KMS {
    /**
     * <p>Decrypts ciphertext. Ciphertext is plaintext that has been previously encrypted by using any of the following operations:</p> <ul> <li> <p> <a>GenerateDataKey</a> </p> </li> <li> <p> <a>GenerateDataKeyWithoutPlaintext</a> </p> </li> <li> <p> <a>Encrypt</a> </p> </li> </ul> <p>Whenever possible, use key policies to give users permission to call the Decrypt operation on the CMK, instead of IAM policies. Otherwise, you might create an IAM user policy that gives the user Decrypt permission on all CMKs. This user could decrypt ciphertext that was encrypted by CMKs in other accounts if the key policy for the cross-account CMK permits it. If you must use an IAM policy for <code>Decrypt</code> permissions, limit the user to particular CMKs or particular trusted accounts.</p> <p>The result of this operation varies with the key state of the CMK. For details, see <a href="http://docs.aws.amazon.com/kms/latest/developerguide/key-state.html">How Key State Affects Use of a Customer Master Key</a> in the <i>AWS Key Management Service Developer Guide</i>.</p>
     *
     * This operation may fail with one of the following errors:
     *   - {NotFoundException} <p>The request was rejected because the specified entity or resource could not be found.</p>
     *   - {DisabledException} <p>The request was rejected because the specified CMK is not enabled.</p>
     *   - {InvalidCiphertextException} <p>The request was rejected because the specified ciphertext, or additional authenticated data incorporated into the ciphertext, such as the encryption context, is corrupted, missing, or otherwise invalid.</p>
     *   - {KeyUnavailableException} <p>The request was rejected because the specified CMK was not available. The request can be retried.</p>
     *   - {DependencyTimeoutException} <p>The system timed out while trying to fulfill the request. The request can be retried.</p>
     *   - {InvalidGrantTokenException} <p>The request was rejected because the specified grant token is not valid.</p>
     *   - {KMSInternalException} <p>The request was rejected because an internal exception occurred. The request can be retried.</p>
     *   - {KMSInvalidStateException} <p>The request was rejected because the state of the specified resource is not valid for this request.</p> <p>For more information about how key state affects the use of a CMK, see <a href="http://docs.aws.amazon.com/kms/latest/developerguide/key-state.html">How Key State Affects Use of a Customer Master Key</a> in the <i>AWS Key Management Service Developer Guide</i>.</p>
     *   - {Error} An error originating from the SDK or customizations rather than the service
     */
    decrypt(args: DecryptInput): Promise<DecryptOutput>;

    /**
     * <p>Encrypts plaintext into ciphertext by using a customer master key (CMK). The <code>Encrypt</code> operation has two primary use cases:</p> <ul> <li> <p>You can encrypt up to 4 kilobytes (4096 bytes) of arbitrary data such as an RSA key, a database password, or other sensitive information.</p> </li> <li> <p>You can use the <code>Encrypt</code> operation to move encrypted data from one AWS region to another. In the first region, generate a data key and use the plaintext key to encrypt the data. Then, in the new region, call the <code>Encrypt</code> method on same plaintext data key. Now, you can safely move the encrypted data and encrypted data key to the new region, and decrypt in the new region when necessary.</p> </li> </ul> <p>You don't need use this operation to encrypt a data key within a region. The <a>GenerateDataKey</a> and <a>GenerateDataKeyWithoutPlaintext</a> operations return an encrypted data key.</p> <p>Also, you don't need to use this operation to encrypt data in your application. You can use the plaintext and encrypted data keys that the <code>GenerateDataKey</code> operation returns.</p> <p>The result of this operation varies with the key state of the CMK. For details, see <a href="http://docs.aws.amazon.com/kms/latest/developerguide/key-state.html">How Key State Affects Use of a Customer Master Key</a> in the <i>AWS Key Management Service Developer Guide</i>.</p> <p>To perform this operation on a CMK in a different AWS account, specify the key ARN or alias ARN in the value of the KeyId parameter.</p>
     *
     * This operation may fail with one of the following errors:
     *   - {NotFoundException} <p>The request was rejected because the specified entity or resource could not be found.</p>
     *   - {DisabledException} <p>The request was rejected because the specified CMK is not enabled.</p>
     *   - {KeyUnavailableException} <p>The request was rejected because the specified CMK was not available. The request can be retried.</p>
     *   - {DependencyTimeoutException} <p>The system timed out while trying to fulfill the request. The request can be retried.</p>
     *   - {InvalidKeyUsageException} <p>The request was rejected because the specified <code>KeySpec</code> value is not valid.</p>
     *   - {InvalidGrantTokenException} <p>The request was rejected because the specified grant token is not valid.</p>
     *   - {KMSInternalException} <p>The request was rejected because an internal exception occurred. The request can be retried.</p>
     *   - {KMSInvalidStateException} <p>The request was rejected because the state of the specified resource is not valid for this request.</p> <p>For more information about how key state affects the use of a CMK, see <a href="http://docs.aws.amazon.com/kms/latest/developerguide/key-state.html">How Key State Affects Use of a Customer Master Key</a> in the <i>AWS Key Management Service Developer Guide</i>.</p>
     *   - {Error} An error originating from the SDK or customizations rather than the service
     */
    encrypt(args: EncryptInput): Promise<EncryptOutput>;

    /**
     * <p>Returns a data encryption key that you can use in your application to encrypt data locally. </p> <p>You must specify the customer master key (CMK) under which to generate the data key. You must also specify the length of the data key using either the <code>KeySpec</code> or <code>NumberOfBytes</code> field. You must specify one field or the other, but not both. For common key lengths (128-bit and 256-bit symmetric keys), we recommend that you use <code>KeySpec</code>. To perform this operation on a CMK in a different AWS account, specify the key ARN or alias ARN in the value of the KeyId parameter.</p> <p>This operation returns a plaintext copy of the data key in the <code>Plaintext</code> field of the response, and an encrypted copy of the data key in the <code>CiphertextBlob</code> field. The data key is encrypted under the CMK specified in the <code>KeyId</code> field of the request. </p> <p>We recommend that you use the following pattern to encrypt data locally in your application:</p> <ol> <li> <p>Use this operation (<code>GenerateDataKey</code>) to get a data encryption key.</p> </li> <li> <p>Use the plaintext data encryption key (returned in the <code>Plaintext</code> field of the response) to encrypt data locally, then erase the plaintext data key from memory.</p> </li> <li> <p>Store the encrypted data key (returned in the <code>CiphertextBlob</code> field of the response) alongside the locally encrypted data.</p> </li> </ol> <p>To decrypt data locally:</p> <ol> <li> <p>Use the <a>Decrypt</a> operation to decrypt the encrypted data key into a plaintext copy of the data key.</p> </li> <li> <p>Use the plaintext data key to decrypt data locally, then erase the plaintext data key from memory.</p> </li> </ol> <p>To return only an encrypted copy of the data key, use <a>GenerateDataKeyWithoutPlaintext</a>. To return a random byte string that is cryptographically secure, use <a>GenerateRandom</a>.</p> <p>If you use the optional <code>EncryptionContext</code> field, you must store at least enough information to be able to reconstruct the full encryption context when you later send the ciphertext to the <a>Decrypt</a> operation. It is a good practice to choose an encryption context that you can reconstruct on the fly to better secure the ciphertext. For more information, see <a href="http://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html">Encryption Context</a> in the <i>AWS Key Management Service Developer Guide</i>.</p> <p>The result of this operation varies with the key state of the CMK. For details, see <a href="http://docs.aws.amazon.com/kms/latest/developerguide/key-state.html">How Key State Affects Use of a Customer Master Key</a> in the <i>AWS Key Management Service Developer Guide</i>.</p>
     *
     * This operation may fail with one of the following errors:
     *   - {NotFoundException} <p>The request was rejected because the specified entity or resource could not be found.</p>
     *   - {DisabledException} <p>The request was rejected because the specified CMK is not enabled.</p>
     *   - {KeyUnavailableException} <p>The request was rejected because the specified CMK was not available. The request can be retried.</p>
     *   - {DependencyTimeoutException} <p>The system timed out while trying to fulfill the request. The request can be retried.</p>
     *   - {InvalidKeyUsageException} <p>The request was rejected because the specified <code>KeySpec</code> value is not valid.</p>
     *   - {InvalidGrantTokenException} <p>The request was rejected because the specified grant token is not valid.</p>
     *   - {KMSInternalException} <p>The request was rejected because an internal exception occurred. The request can be retried.</p>
     *   - {KMSInvalidStateException} <p>The request was rejected because the state of the specified resource is not valid for this request.</p> <p>For more information about how key state affects the use of a CMK, see <a href="http://docs.aws.amazon.com/kms/latest/developerguide/key-state.html">How Key State Affects Use of a Customer Master Key</a> in the <i>AWS Key Management Service Developer Guide</i>.</p>
     *   - {Error} An error originating from the SDK or customizations rather than the service
     */
    generateDataKey(args: GenerateDataKeyInput): Promise<GenerateDataKeyOutput>;

}
