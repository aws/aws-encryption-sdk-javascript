# AWS Encryption SDK for Javascript Web Crypto examples

This repository holds examples for encrypt and decrypt in Node.js.
These examples are intended to work so you can experiment with functional code.

#NOTE
The CMK's in these examples *are only* for example.  They *are public*.
Replace these CMK's with your own.

## KMS Simple

This is the simples example.
It encrypts and decrypts a simple string with KMS.

## KMS Stream

An example of encrypting a file stream with KMS.

## KMS Regional Discovery

KMS Keyrings can be put in `discovery` mode.
This means that it will attempt to connect to any region.
This is not always what you want.
Perhapses for performance you want to limit attempts to a set of "close" regions.
Perhapses for policy reason you want to exclude some regions.

## RSA Simple

Sometimes you may want to use an RSA key to exchange secrets.
This has some advantages, but comes with a heaved key management cost.
If you can use KMS, the context guaranties are generally worth it.
However, I still want to provide an example incase this fits your use case.
