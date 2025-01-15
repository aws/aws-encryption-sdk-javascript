# H-Keyring Intern Demo Guide

This guide provides detailed instructions on running the intern demos for the H-Keyring.

## Prerequisites

Before running the demos, navigate to the following directory:

```bash
cd /private-aws-encryption-sdk-javascript-staging/modules/example-node/
```

**Note:** All file paths in the CLI arguments must be absolute paths.

## Demo 1: Performance Comparison between KMS Keyring and H-Keyring

This demo compares the performance of the KMS Keyring and H-Keyring. In each roundtrip, a random string is generated, encrypted with a keyring, and then decrypted, expecting the original string to be returned.

The program logs roundtrip metrics for both the KMS Keyring and H-Keyring, including runtime, call volume, and success rate.

### Run the Demo

To run the performance comparison demo, use the following command:

```bash
npx ts-node hkr-demo/hkr_vs_regular.demo.ts --numRoundTrips=<number of roundtrips>
```

**Note:** The number of roundtrips defaults to 10 if not specified.

## Demo 2: Interoperability Test

This demo demonstrates the interoperability between the JS H-Keyring and other H-Keyrings.

### General Command

To encrypt a data file or decrypt an encrypted file using the JS H-Keyring, use the following command format:

```bash
npx ts-node hkr-demo/interop.demo.ts <encrypt or decrypt> <input filepath> <output filepath>
```

### Encrypting a Data File

To encrypt a data file with the JS H-Keyring, run:

```bash
npx ts-node hkr-demo/interop.demo.ts encrypt <data filepath> <encrypted filepath>
```

### Decrypting an Encrypted File

To decrypt an encrypted file with the JS H-Keyring, run:

```bash
npx ts-node hkr-demo/interop.demo.ts decrypt <encrypted filepath> <decrypted filepath>
```

## Demo 3: Multi-Tenancy

This demo showcases multi-tenant data isolation within a single keyring. You will observe failures when encrypting with tenant A and decrypting with tenant B (or vice versa). Tenant A and B are mapped to hard-coded branch IDs within the demo code in `./hkr-demo/multi_tenant.demo.ts`.

### General Command

To encrypt or decrypt with tenant A or B, use the following command format:

```bash
npx ts-node hkr-demo/multi_tenant.demo.ts --operation=<encrypt or decrypt> --inputFile=<input filepath> --outputFile=<output filepath> --tenant=<A or B>
```

### Encrypting with Tenant A

```bash
npx ts-node hkr-demo/multi_tenant.demo.ts --operation=encrypt --inputFile=<data filepath> --outputFile=<encrypted filepath> --tenant=A
```

### Decrypting with Tenant A

```bash
npx ts-node hkr-demo/multi_tenant.demo.ts --operation=decrypt --inputFile=<encrypted filepath> --outputFile=<decrypted filepath> --tenant=A
```

### Encrypting with Tenant B

```bash
npx ts-node hkr-demo/multi_tenant.demo.ts --operation=encrypt --inputFile=<data filepath> --outputFile=<encrypted filepath> --tenant=B
```

### Decrypting with Tenant B

```bash
npx ts-node hkr-demo/multi_tenant.demo.ts --operation=decrypt --inputFile=<encrypted filepath> --outputFile=<decrypted filepath> --tenant=B
```

### Example: Demonstrating Tenant Data Isolation

To observe tenant data isolation, run the following commands:

```bash
npx ts-node hkr-demo/multi_tenant.demo.ts --operation=encrypt --inputFile=<data filepath> --outputFile=<encrypted filepath> --tenant=A
npx ts-node hkr-demo/multi_tenant.demo.ts --operation=decrypt --inputFile=<encrypted filepath> --outputFile=<decrypted filepath> --tenant=B
```

An error will occur, demonstrating the isolation between tenant encryption.
