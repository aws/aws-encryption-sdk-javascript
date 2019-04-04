import * as __aws_sdk_types from '@aws-sdk/types';

export interface KMSConfiguration {
    /**
     * The function that will be used to convert a base64-encoded string to a byte array
     */
    base64Decoder?: __aws_sdk_types.Decoder;

    /**
     * The function that will be used to convert binary data to a base64-encoded string
     */
    base64Encoder?: __aws_sdk_types.Encoder;

    /**
     * The credentials used to sign requests.
     *
     * If no static credentials are supplied, the SDK will attempt to credentials from known environment variables, from shared configuration and credentials files, and from the EC2 Instance Metadata Service, in that order.
     */
    credentials?: __aws_sdk_types.Credentials|__aws_sdk_types.Provider<__aws_sdk_types.Credentials>;

    /**
     * A function that determines how long (in milliseconds) the SDK should wait before retrying a request
     */
    delayDecider?: __aws_sdk_types.DelayDecider;

    /**
     * The fully qualified endpoint of the webservice. This is only required when using a custom endpoint (for example, when using a local version of S3).
     */
    endpoint?: string|__aws_sdk_types.HttpEndpoint|__aws_sdk_types.Provider<__aws_sdk_types.HttpEndpoint>;

    /**
     * The endpoint provider to call if no endpoint is provided
     */
    endpointProvider?: any;

    // /**
    //  * The handler to use as the core of the client's middleware stack
    //  */
    // handler?: __aws_sdk_types.Terminalware<any, _stream.Readable>;

    // /**
    //  * The HTTP handler to use
    //  */
    // httpHandler?: __aws_sdk_types.HttpHandler<_stream.Readable>;

    /**
     * The maximum number of redirects to follow for a service request. Set to `0` to disable retries.
     */
    maxRedirects?: number;

    /**
     * The maximum number of times requests that encounter potentially transient failures should be retried
     */
    maxRetries?: number;

    /**
     * The configuration profile to use.
     */
    profile?: string;

    /**
     * The AWS region to which this client will send requests
     */
    region?: string|__aws_sdk_types.Provider<string>;

    /**
     * A function that determines whether an error is retryable
     */
    retryDecider?: __aws_sdk_types.RetryDecider;

    /**
     * A constructor for a class implementing the @aws-sdk/types.Hash interface that computes the SHA-256 HMAC or checksum of a string or binary buffer
     */
    sha256?: __aws_sdk_types.HashConstructor;

    /**
     * The signer to use when signing requests.
     */
    signer?: __aws_sdk_types.RequestSigner;

    /**
     * The service name with which to sign requests.
     */
    signingName?: string;

    /**
     * Whether SSL is enabled for requests.
     */
    sslEnabled?: boolean;

    // /**
    //  * A function that converts a stream into an array of bytes.
    //  */
    // streamCollector?: __aws_sdk_types.StreamCollector<_stream.Readable>;

    /**
     * The function that will be used to convert strings into HTTP endpoints
     */
    urlParser?: __aws_sdk_types.UrlParser;

    /**
     * The function that will be used to convert a UTF8-encoded string to a byte array
     */
    utf8Decoder?: __aws_sdk_types.Decoder;

    /**
     * The function that will be used to convert binary data to a UTF-8 encoded string
     */
    utf8Encoder?: __aws_sdk_types.Encoder;
}
