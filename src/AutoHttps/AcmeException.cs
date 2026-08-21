using System;

namespace AutoHttps;

/// <summary>
/// Represents an error returned by an ACME certificate authority.
/// </summary>
public class AcmeException : Exception
{
    /// <summary>Initializes a new instance of the <see cref="AcmeException"/> class.</summary>
    public AcmeException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AcmeException"/> class.</summary>
    /// <param name="message">The error message.</param>
    public AcmeException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AcmeException"/> class.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The underlying cause.</param>
    public AcmeException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AcmeException"/> class.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorType">The ACME error URN, for example <c>urn:ietf:params:acme:error:rateLimited</c>.</param>
    /// <param name="detail">The human readable detail supplied by the server.</param>
    /// <param name="statusCode">The HTTP status code returned with the error.</param>
    public AcmeException(string message, string? errorType, string? detail, int? statusCode)
        : base(message)
    {
        ErrorType = errorType;
        Detail = detail;
        StatusCode = statusCode;
    }

    /// <summary>Gets the ACME error URN, when the server supplied one.</summary>
    public string? ErrorType { get; }

    /// <summary>Gets the human readable detail supplied by the server.</summary>
    public string? Detail { get; }

    /// <summary>Gets the HTTP status code returned with the error.</summary>
    public int? StatusCode { get; }
}

/// <summary>
/// Thrown when the certificate authority rejects a request because a rate limit was exceeded.
/// </summary>
public sealed class AcmeRateLimitException : AcmeException
{
    /// <summary>Initializes a new instance of the <see cref="AcmeRateLimitException"/> class.</summary>
    public AcmeRateLimitException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AcmeRateLimitException"/> class.</summary>
    /// <param name="message">The error message.</param>
    public AcmeRateLimitException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AcmeRateLimitException"/> class.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The underlying cause.</param>
    public AcmeRateLimitException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AcmeRateLimitException"/> class.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="detail">The human readable detail supplied by the server.</param>
    /// <param name="retryAfter">When the request may be retried, if the server said so.</param>
    public AcmeRateLimitException(string message, string? detail, DateTimeOffset? retryAfter)
        : base(message, Acme.AcmeErrorTypes.RateLimited, detail, 429)
    {
        RetryAfter = retryAfter;
    }

    /// <summary>Gets the time at which the request may be retried, when the server supplied one.</summary>
    public DateTimeOffset? RetryAfter { get; }
}
